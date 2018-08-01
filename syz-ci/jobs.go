// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

type JobProcessor struct {
	name            string
	managers        []*Manager
	dash            *dashapi.Dashboard
	syzkallerRepo   string
	syzkallerBranch string
}

func newJobProcessor(cfg *Config, managers []*Manager) *JobProcessor {
	jp := &JobProcessor{
		name:            fmt.Sprintf("%v-job", cfg.Name),
		managers:        managers,
		syzkallerRepo:   cfg.SyzkallerRepo,
		syzkallerBranch: cfg.SyzkallerBranch,
	}
	if cfg.DashboardAddr != "" && cfg.DashboardClient != "" {
		jp.dash = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	}
	return jp
}

func (jp *JobProcessor) loop(stop chan struct{}) {
	if jp.dash == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			jp.poll()
		case <-stop:
			log.Logf(0, "job loop stopped")
			return
		}
	}
}

func (jp *JobProcessor) poll() {
	var names []string
	for _, mgr := range jp.managers {
		names = append(names, mgr.name)
	}
	req, err := jp.dash.JobPoll(names)
	if err != nil {
		jp.Errorf("failed to poll jobs: %v", err)
		return
	}
	if req.ID == "" {
		return
	}
	var mgr *Manager
	for _, m := range jp.managers {
		if m.name == req.Manager {
			mgr = m
			break
		}
	}
	if mgr == nil {
		jp.Errorf("got job for unknown manager: %v", req.Manager)
		return
	}
	job := &Job{
		req: req,
		mgr: mgr,
	}
	log.Logf(0, "starting job %v for manager %v on %v/%v",
		req.ID, req.Manager, req.KernelRepo, req.KernelBranch)
	resp := jp.process(job)
	log.Logf(0, "done job %v: commit %v, crash %q, error: %s",
		resp.ID, resp.Build.KernelCommit, resp.CrashTitle, resp.Error)
	if err := jp.dash.JobDone(resp); err != nil {
		jp.Errorf("failed to mark job as done: %v", err)
		return
	}
}

type Job struct {
	req  *dashapi.JobPollResp
	resp *dashapi.JobDoneReq
	mgr  *Manager
}

func (jp *JobProcessor) process(job *Job) *dashapi.JobDoneReq {
	req, mgr := job.req, job.mgr
	build := dashapi.Build{
		Manager:         mgr.name,
		ID:              req.ID,
		OS:              mgr.managercfg.TargetOS,
		Arch:            mgr.managercfg.TargetArch,
		VMArch:          mgr.managercfg.TargetVMArch,
		CompilerID:      mgr.compilerID,
		KernelRepo:      req.KernelRepo,
		KernelBranch:    req.KernelBranch,
		KernelCommit:    "[unknown]",
		SyzkallerCommit: "[unknown]",
	}
	job.resp = &dashapi.JobDoneReq{
		ID:    req.ID,
		Build: build,
	}
	required := []struct {
		name string
		ok   bool
	}{
		{"kernel repository", req.KernelRepo != ""},
		{"kernel branch", req.KernelBranch != ""},
		{"kernel config", len(req.KernelConfig) != 0},
		{"syzkaller commit", req.SyzkallerCommit != ""},
		{"reproducer options", len(req.ReproOpts) != 0},
		{"reproducer program", len(req.ReproSyz) != 0},
	}
	for _, req := range required {
		if !req.ok {
			job.resp.Error = []byte(req.name + " is empty")
			jp.Errorf("%s", job.resp.Error)
			return job.resp
		}
	}
	// TODO(dvyukov): this will only work for qemu/gce,
	// because e.g. adb requires unique device IDs and we can't use what
	// manager already uses. For qemu/gce this is also bad, because we
	// override resource limits specified in config (e.g. can OOM), but works.
	switch typ := mgr.managercfg.Type; typ {
	case "gce", "qemu":
	default:
		job.resp.Error = []byte(fmt.Sprintf("testing is not yet supported for %v machine type.", typ))
		jp.Errorf("%s", job.resp.Error)
		return job.resp
	}
	if err := jp.test(job); err != nil {
		job.resp.Error = []byte(err.Error())
	}
	return job.resp
}

func (jp *JobProcessor) test(job *Job) error {
	kernelBuildSem <- struct{}{}
	defer func() { <-kernelBuildSem }()
	req, resp, mgr := job.req, job.resp, job.mgr

	dir := osutil.Abs(filepath.Join("jobs", mgr.managercfg.TargetOS))
	kernelDir := filepath.Join(dir, "kernel")

	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Name += "-job"
	mgrcfg.Workdir = filepath.Join(dir, "workdir")
	mgrcfg.KernelSrc = kernelDir
	mgrcfg.Syzkaller = filepath.Join(dir, "gopath", "src", "github.com", "google", "syzkaller")

	os.RemoveAll(mgrcfg.Workdir)
	defer os.RemoveAll(mgrcfg.Workdir)

	env, err := instance.NewEnv(mgrcfg)
	if err != nil {
		return err
	}
	log.Logf(0, "job: building syzkaller on %v...", req.SyzkallerCommit)
	resp.Build.SyzkallerCommit = req.SyzkallerCommit
	if err := env.BuildSyzkaller(jp.syzkallerRepo, req.SyzkallerCommit); err != nil {
		return err
	}

	log.Logf(0, "job: fetching kernel...")
	repo, err := vcs.NewRepo(mgrcfg.TargetOS, mgrcfg.Type, kernelDir)
	if err != nil {
		return fmt.Errorf("failed to create kernel repo: %v", err)
	}
	var kernelCommit *vcs.Commit
	if vcs.CheckCommitHash(req.KernelBranch) {
		kernelCommit, err = repo.CheckoutCommit(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v on commit %v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
		resp.Build.KernelBranch = ""
	} else {
		kernelCommit, err = repo.CheckoutBranch(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v/%v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
	}
	resp.Build.KernelCommit = kernelCommit.Hash
	resp.Build.KernelCommitTitle = kernelCommit.Title
	resp.Build.KernelCommitDate = kernelCommit.Date

	if err := build.Clean(mgrcfg.TargetOS, mgrcfg.TargetVMArch, mgrcfg.Type, kernelDir); err != nil {
		return fmt.Errorf("kernel clean failed: %v", err)
	}
	if len(req.Patch) != 0 {
		if err := vcs.Patch(kernelDir, req.Patch); err != nil {
			return err
		}
	}

	log.Logf(0, "job: building kernel...")
	if err := env.BuildKernel(mgr.mgrcfg.Compiler, mgr.mgrcfg.Userspace, mgr.mgrcfg.KernelCmdline,
		mgr.mgrcfg.KernelSysctl, req.KernelConfig); err != nil {
		return err
	}
	resp.Build.KernelConfig, err = ioutil.ReadFile(filepath.Join(mgrcfg.KernelSrc, ".config"))
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	log.Logf(0, "job: testing...")
	results, err := env.Test(3, req.ReproSyz, req.ReproOpts, req.ReproC)
	if err != nil {
		return err
	}
	// We can have transient errors and other errors of different types.
	// We need to avoid reporting transient "failed to boot" or "failed to copy binary" errors.
	// If any of the instances crash during testing, we report this with the highest priority.
	// Then if any of the runs succeed, we report that (to avoid transient errors).
	// If all instances failed to boot, then we report one of these errors.
	anySuccess := false
	var anyErr, testErr error
	for _, res := range results {
		if res == nil {
			anySuccess = true
			continue
		}
		anyErr = res
		switch err := res.(type) {
		case *instance.TestError:
			// We should not put rep into resp.CrashTitle/CrashReport,
			// because that will be treated as patch not fixing the bug.
			if rep := err.Report; rep != nil {
				testErr = fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
			} else {
				testErr = fmt.Errorf("%v\n\n%s", err.Title, err.Output)
			}
		case *instance.CrashError:
			resp.CrashTitle = err.Report.Title
			resp.CrashReport = err.Report.Report
			resp.CrashLog = err.Report.Output
			return nil
		}
	}
	if anySuccess {
		return nil
	}
	if testErr != nil {
		return testErr
	}
	return anyErr
}

// Errorf logs non-fatal error and sends it to dashboard.
func (jp *JobProcessor) Errorf(msg string, args ...interface{}) {
	log.Logf(0, "job: "+msg, args...)
	if jp.dash != nil {
		jp.dash.LogError(jp.name, msg, args...)
	}
}
