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
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/git"
	"github.com/google/syzkaller/pkg/kernel"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
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
	req    *dashapi.JobPollResp
	resp   *dashapi.JobDoneReq
	mgr    *Manager
	mgrcfg *mgrconfig.Config
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
	if err := jp.buildImage(job); err != nil {
		job.resp.Error = []byte(err.Error())
		return job.resp
	}
	var err error
	for try := 0; try < 3; try++ {
		if err = jp.test(job); err == nil {
			break
		}
		log.Logf(0, "job: testing failed, trying once again\n%v", err)
	}
	if err != nil {
		job.resp.Error = []byte(err.Error())
	}
	return job.resp
}

func (jp *JobProcessor) buildImage(job *Job) error {
	kernelBuildSem <- struct{}{}
	defer func() { <-kernelBuildSem }()
	req, resp, mgr := job.req, job.resp, job.mgr

	dir := osutil.Abs(filepath.Join("jobs", mgr.managercfg.TargetOS))
	kernelDir := filepath.Join(dir, "kernel")
	if err := osutil.MkdirAll(kernelDir); err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	imageDir := filepath.Join(dir, "image")
	os.RemoveAll(imageDir)
	if err := osutil.MkdirAll(imageDir); err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	workDir := filepath.Join(dir, "workdir")
	os.RemoveAll(workDir)
	if err := osutil.MkdirAll(workDir); err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	gopathDir := filepath.Join(dir, "gopath")
	syzkallerDir := filepath.Join(gopathDir, "src", "github.com", "google", "syzkaller")
	if err := osutil.MkdirAll(syzkallerDir); err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}

	log.Logf(0, "job: fetching syzkaller on %v...", req.SyzkallerCommit)
	_, err := git.CheckoutCommit(syzkallerDir, jp.syzkallerRepo, req.SyzkallerCommit)
	if err != nil {
		return fmt.Errorf("failed to checkout syzkaller repo: %v", err)
	}

	log.Logf(0, "job: building syzkaller...")
	cmd := osutil.Command("make", "target")
	cmd.Dir = syzkallerDir
	cmd.Env = append([]string{}, os.Environ()...)
	cmd.Env = append(cmd.Env,
		"GOPATH="+gopathDir,
		"TARGETOS="+mgr.managercfg.TargetOS,
		"TARGETVMARCH="+mgr.managercfg.TargetVMArch,
		"TARGETARCH="+mgr.managercfg.TargetArch,
	)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("syzkaller build failed: %v", err)
	}
	resp.Build.SyzkallerCommit = req.SyzkallerCommit

	log.Logf(0, "job: fetching kernel...")
	var kernelCommit *git.Commit
	if git.CheckCommitHash(req.KernelBranch) {
		kernelCommit, err = git.CheckoutCommit(kernelDir, req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v on commit %v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
		resp.Build.KernelBranch = ""
	} else {
		kernelCommit, err = git.CheckoutBranch(kernelDir, req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v/%v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
	}
	resp.Build.KernelCommit = kernelCommit.Hash
	resp.Build.KernelCommitTitle = kernelCommit.Title
	resp.Build.KernelCommitDate = kernelCommit.Date

	if err := kernel.Clean(kernelDir); err != nil {
		return fmt.Errorf("kernel clean failed: %v", err)
	}
	if len(req.Patch) != 0 {
		if err := git.Patch(kernelDir, req.Patch); err != nil {
			return err
		}
	}

	log.Logf(0, "job: building kernel...")
	if err := kernel.Build(kernelDir, mgr.mgrcfg.Compiler, req.KernelConfig); err != nil {
		return fmt.Errorf("kernel build failed: %v", err)
	}
	resp.Build.KernelConfig, err = ioutil.ReadFile(filepath.Join(kernelDir, ".config"))
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	log.Logf(0, "job: creating image...")
	image := filepath.Join(imageDir, "image")
	key := filepath.Join(imageDir, "key")
	err = kernel.CreateImage(kernelDir, mgr.mgrcfg.Userspace,
		mgr.mgrcfg.KernelCmdline, mgr.mgrcfg.KernelSysctl, image, key)
	if err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}

	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Name += "-job"
	mgrcfg.Workdir = workDir
	mgrcfg.Vmlinux = filepath.Join(kernelDir, "vmlinux")
	mgrcfg.KernelSrc = kernelDir
	mgrcfg.Syzkaller = syzkallerDir
	mgrcfg.Image = image
	mgrcfg.SSHKey = key
	if err := mgrconfig.Complete(mgrcfg); err != nil {
		return fmt.Errorf("bad manager config: %v", err)
	}
	job.mgrcfg = mgrcfg
	return nil
}

func (jp *JobProcessor) test(job *Job) error {
	req, mgrcfg := job.req, job.mgrcfg

	log.Logf(0, "job: booting VM...")
	inst, reporter, rep, err := bootInstance(mgrcfg)
	if err != nil {
		return err
	}
	if rep != nil {
		// We should not put rep into resp.CrashTitle/CrashReport,
		// because that will be treated as patch not fixing the bug.
		return fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
	}
	defer inst.Close()

	log.Logf(0, "job: testing instance...")
	rep, err = testInstance(inst, reporter, mgrcfg)
	if err != nil {
		return err
	}
	if rep != nil {
		// We should not put rep into resp.CrashTitle/CrashReport,
		// because that will be treated as patch not fixing the bug.
		return fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
	}

	log.Logf(0, "job: copying binaries...")
	execprogBin, err := inst.Copy(mgrcfg.SyzExecprogBin)
	if err != nil {
		return fmt.Errorf("failed to copy test binary to VM: %v", err)
	}
	executorBin, err := inst.Copy(mgrcfg.SyzExecutorBin)
	if err != nil {
		return fmt.Errorf("failed to copy test binary to VM: %v", err)
	}
	progFile := filepath.Join(mgrcfg.Workdir, "repro.prog")
	if err := osutil.WriteFile(progFile, req.ReproSyz); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}
	vmProgFile, err := inst.Copy(progFile)
	if err != nil {
		return fmt.Errorf("failed to copy to VM: %v", err)
	}

	log.Logf(0, "job: testing syzkaller program...")
	opts, err := csource.DeserializeOptions(req.ReproOpts)
	if err != nil {
		return err
	}
	// Combine repro options and default options in a way that increases chances to reproduce the crash.
	// First, we always enable threaded/collide as it should be [almost] strictly better.
	// Executor does not support empty sandbox, so we use none instead.
	// Finally, always use repeat and multiple procs.
	if opts.Sandbox == "" {
		opts.Sandbox = "none"
	}
	if !opts.Fault {
		opts.FaultCall = -1
	}
	cmdSyz := fmt.Sprintf("%v -executor %v -arch=%v -procs=%v -sandbox=%v"+
		" -fault_call=%v -fault_nth=%v -repeat=0 -cover=0 %v",
		execprogBin, executorBin, mgrcfg.TargetArch, mgrcfg.Procs, opts.Sandbox,
		opts.FaultCall, opts.FaultNth, vmProgFile)
	crashed, err := jp.testProgram(job, inst, cmdSyz, reporter, 7*time.Minute)
	if crashed || err != nil {
		return err
	}

	if len(req.ReproC) != 0 {
		log.Logf(0, "job: testing C program...")
		cFile := filepath.Join(mgrcfg.Workdir, "repro.c")
		if err := osutil.WriteFile(cFile, req.ReproC); err != nil {
			return fmt.Errorf("failed to write temp file: %v", err)
		}
		target, err := prog.GetTarget(mgrcfg.TargetOS, mgrcfg.TargetArch)
		if err != nil {
			return err
		}
		bin, err := csource.Build(target, "c", cFile)
		if err != nil {
			return err
		}
		vmBin, err := inst.Copy(bin)
		if err != nil {
			return fmt.Errorf("failed to copy test binary to VM: %v", err)
		}
		// We should test for longer (e.g. 5 mins), but the problem is that
		// reproducer does not print anything, so after 3 mins we detect "no output".
		crashed, err := jp.testProgram(job, inst, vmBin, reporter, time.Minute)
		if crashed || err != nil {
			return err
		}
	}
	return nil
}

func (jp *JobProcessor) testProgram(job *Job, inst *vm.Instance, command string,
	reporter report.Reporter, testTime time.Duration) (bool, error) {
	outc, errc, err := inst.Run(testTime, nil, command)
	if err != nil {
		return false, fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := vm.MonitorExecution(outc, errc, reporter, true)
	if rep == nil {
		return false, nil
	}
	if err := reporter.Symbolize(rep); err != nil {
		jp.Errorf("failed to symbolize report: %v", err)
	}
	job.resp.CrashTitle = rep.Title
	job.resp.CrashReport = rep.Report
	job.resp.CrashLog = rep.Output
	return true, nil
}

// Errorf logs non-fatal error and sends it to dashboard.
func (jp *JobProcessor) Errorf(msg string, args ...interface{}) {
	log.Logf(0, "job: "+msg, args...)
	if jp.dash != nil {
		jp.dash.LogError(jp.name, msg, args...)
	}
}
