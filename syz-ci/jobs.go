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
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/git"
	"github.com/google/syzkaller/pkg/kernel"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
)

type JobProcessor struct {
	managers []*Manager
	dash     *dashapi.Dashboard
}

func newJobProcessor(cfg *Config, managers []*Manager) *JobProcessor {
	jp := &JobProcessor{
		managers: managers,
	}
	if cfg.Dashboard_Addr != "" && cfg.Dashboard_Client != "" {
		jp.dash = dashapi.New(cfg.Dashboard_Client, cfg.Dashboard_Addr, cfg.Dashboard_Key)
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
			Logf(0, "job loop stopped")
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
		Logf(0, "failed to poll jobs: %v", err)
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
		Logf(0, "got job for unknown manager: %v", req.Manager)
		return
	}
	job := &Job{
		req: req,
		mgr: mgr,
	}
	Logf(0, "starting job %v for manager %v on %v/%v",
		req.ID, req.Manager, req.KernelRepo, req.KernelBranch)
	resp := job.process()
	Logf(0, "done job %v: commit %v, crash %q, error: %s",
		resp.ID, resp.Build.KernelCommit, resp.CrashTitle, resp.Error)
	if err := jp.dash.JobDone(resp); err != nil {
		Logf(0, "failed to mark job as done: %v", err)
		return
	}
}

type Job struct {
	req    *dashapi.JobPollResp
	resp   *dashapi.JobDoneReq
	mgr    *Manager
	mgrcfg *mgrconfig.Config
}

func (job *Job) process() *dashapi.JobDoneReq {
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
		{"test patch", len(req.Patch) != 0},
		{"reproducer options", len(req.ReproOpts) != 0},
		{"reproducer program", len(req.ReproSyz) != 0},
	}
	for _, req := range required {
		if !req.ok {
			job.resp.Error = []byte(req.name + " is empty")
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
		return job.resp
	}
	if err := job.buildImage(); err != nil {
		job.resp.Error = []byte(err.Error())
		return job.resp
	}
	if err := job.test(); err != nil {
		job.resp.Error = []byte(err.Error())
		return job.resp
	}
	return job.resp
}

func (job *Job) buildImage() error {
	kernelBuildSem <- struct{}{}
	defer func() { <-kernelBuildSem }()
	req, resp, mgr := job.req, job.resp, job.mgr

	// TODO(dvyukov): build syzkaller on req.SyzkallerCommit and use it.
	// Newer syzkaller may not parse an old reproducer program.
	syzkallerCommit, _ := readTag(filepath.FromSlash("syzkaller/current/tag"))
	if syzkallerCommit == "" {
		return fmt.Errorf("failed to read syzkaller build tag")
	}
	resp.Build.SyzkallerCommit = syzkallerCommit

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

	Logf(0, "job: fetching kernel...")
	kernelCommit, err := git.Checkout(kernelDir, req.KernelRepo, req.KernelBranch)
	if err != nil {
		return fmt.Errorf("failed to checkout kernel repo: %v", err)
	}
	resp.Build.KernelCommit = kernelCommit

	if err := git.Patch(kernelDir, req.Patch); err != nil {
		return err
	}

	Logf(0, "job: building kernel...")
	configFile := filepath.Join(dir, "kernel.config")
	if err := osutil.WriteFile(configFile, req.KernelConfig); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}
	if err := kernel.Build(kernelDir, mgr.mgrcfg.Compiler, configFile); err != nil {
		return fmt.Errorf("kernel build failed: %v", err)
	}
	kernelConfig, err := ioutil.ReadFile(filepath.Join(kernelDir, ".config"))
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	resp.Build.KernelConfig = kernelConfig

	Logf(0, "job: creating image...")
	image := filepath.Join(imageDir, "image")
	key := filepath.Join(imageDir, "key")
	err = kernel.CreateImage(kernelDir, mgr.mgrcfg.Userspace,
		mgr.mgrcfg.Kernel_Cmdline, mgr.mgrcfg.Kernel_Sysctl, image, key)
	if err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}
	// TODO(dvyukov): test that the image is good (boots and we can ssh into it).

	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Name += "-job"
	mgrcfg.Workdir = workDir
	mgrcfg.Vmlinux = filepath.Join(kernelDir, "vmlinux")
	mgrcfg.Kernel_Src = kernelDir
	mgrcfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	mgrcfg.Image = image
	mgrcfg.Sshkey = key

	// Reload config to fill derived fields (ugly hack).
	cfgdata, err := config.SaveData(mgrcfg)
	if err != nil {
		return fmt.Errorf("failed to save manager config: %v", err)
	}
	if job.mgrcfg, err = mgrconfig.LoadData(cfgdata); err != nil {
		return fmt.Errorf("failed to reload manager config: %v", err)
	}
	return nil
}

func (job *Job) test() error {
	req, mgrcfg := job.req, job.mgrcfg

	Logf(0, "job: booting VM...")
	vmEnv := mgrconfig.CreateVMEnv(mgrcfg, false)
	vmPool, err := vm.Create(mgrcfg.Type, vmEnv)
	if err != nil {
		return fmt.Errorf("failed to create VM pool: %v", err)
	}
	inst, err := vmPool.Create(0)
	if err != nil {
		return fmt.Errorf("failed to create VM: %v", err)
	}
	defer inst.Close()

	Logf(0, "job: copying binaries...")
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
	reporter, err := report.NewReporter(mgrcfg.TargetOS, mgrcfg.Kernel_Src,
		filepath.Dir(mgrcfg.Vmlinux), nil, mgrcfg.ParsedIgnores)
	if err != nil {
		return err
	}

	Logf(0, "job: testing syzkaller program...")
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
	crashed, err := job.testProgram(inst, cmdSyz, reporter, 7*time.Minute)
	if crashed || err != nil {
		return err
	}

	if len(req.ReproC) != 0 {
		Logf(0, "job: testing C program...")
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
		crashed, err := job.testProgram(inst, vmBin, reporter, time.Minute)
		if crashed || err != nil {
			return err
		}
	}
	return nil
}

func (job *Job) testProgram(inst *vm.Instance, command string, reporter report.Reporter,
	testTime time.Duration) (bool, error) {
	outc, errc, err := inst.Run(testTime, nil, command)
	if err != nil {
		return false, fmt.Errorf("failed to run binary in VM: %v", err)
	}
	title, report, output, crashed, _ := vm.MonitorExecution(outc, errc, reporter)
	if crashed {
		job.resp.CrashTitle = title
		job.resp.CrashReport = report
		job.resp.CrashLog = output
	}
	return crashed, nil
}
