// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package instance provides helper functions for creation of temporal instances
// used for testing of images, patches and bisection.
package instance

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

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

type Env struct {
	cfg *mgrconfig.Config
}

func NewEnv(cfg *mgrconfig.Config) (*Env, error) {
	switch cfg.Type {
	case "gce", "qemu":
	default:
		return nil, fmt.Errorf("test instances can only work with qemu/gce")
	}
	if cfg.Workdir == "" {
		return nil, fmt.Errorf("workdir path is empty")
	}
	if cfg.KernelSrc == "" {
		return nil, fmt.Errorf("kernel src path is empty")
	}
	if cfg.Syzkaller == "" {
		return nil, fmt.Errorf("syzkaller path is empty")
	}
	if err := osutil.MkdirAll(cfg.Workdir); err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %v", err)
	}
	env := &Env{
		cfg: cfg,
	}
	return env, nil
}

func (env *Env) BuildSyzkaller(repo, commit string) error {
	cfg := env.cfg
	srcIndex := strings.LastIndex(cfg.Syzkaller, "/src/")
	if srcIndex == -1 {
		return fmt.Errorf("syzkaller path %q is not in GOPATH", cfg.Syzkaller)
	}
	if _, err := git.CheckoutCommit(cfg.Syzkaller, repo, commit); err != nil {
		return fmt.Errorf("failed to checkout syzkaller repo: %v", err)
	}
	cmd := osutil.Command("make", "target")
	cmd.Dir = cfg.Syzkaller
	cmd.Env = append([]string{}, os.Environ()...)
	cmd.Env = append(cmd.Env,
		"GOPATH="+cfg.Syzkaller[:srcIndex],
		"TARGETOS="+cfg.TargetOS,
		"TARGETVMARCH="+cfg.TargetVMArch,
		"TARGETARCH="+cfg.TargetArch,
	)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("syzkaller build failed: %v", err)
	}
	return nil
}

func (env *Env) BuildKernel(compilerBin, userspaceDir, cmdlineFile, sysctlFile string, kernelConfig []byte) error {
	cfg := env.cfg
	if err := kernel.Build(cfg.KernelSrc, compilerBin, kernelConfig); err != nil {
		return osutil.PrependContext("kernel build failed", err)
	}
	cfg.Vmlinux = filepath.Join(cfg.KernelSrc, "vmlinux")
	cfg.Image = filepath.Join(cfg.Workdir, "syz-image")
	cfg.SSHKey = filepath.Join(cfg.Workdir, "syz-key")
	if err := kernel.CreateImage(cfg.TargetOS, cfg.TargetVMArch, cfg.Type,
		cfg.KernelSrc, userspaceDir, cmdlineFile, sysctlFile, cfg.Image, cfg.SSHKey); err != nil {
		return osutil.PrependContext("image build failed", err)
	}
	return nil
}

type TestError struct {
	Boot   bool // says if the error happened during booting or during instance testing
	Title  string
	Output []byte
	Report *report.Report
}

func (err *TestError) Error() string {
	return err.Title
}

type CrashError struct {
	Report *report.Report
}

func (err *CrashError) Error() string {
	return err.Report.Title
}

// Test boots numVMs VMs, tests basic kernel operation, and optionally tests the provided reproducer.
// TestError is returned if there is a problem with kernel/image (crash, reboot loop, etc).
// CrashError is returned if the reproducer crashes kernel.
func (env *Env) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	if err := mgrconfig.Complete(env.cfg); err != nil {
		return nil, err
	}
	reporter, err := report.NewReporter(env.cfg.TargetOS, env.cfg.KernelSrc,
		filepath.Dir(env.cfg.Vmlinux), nil, env.cfg.ParsedIgnores)
	if err != nil {
		return nil, err
	}
	vmEnv := mgrconfig.CreateVMEnv(env.cfg, false)
	vmPool, err := vm.Create(env.cfg.Type, vmEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %v", err)
	}
	if n := vmPool.Count(); numVMs > n {
		numVMs = n
	}
	res := make(chan error, numVMs)
	for i := 0; i < numVMs; i++ {
		inst := &inst{
			cfg:       env.cfg,
			reporter:  reporter,
			vmPool:    vmPool,
			vmIndex:   i,
			reproSyz:  reproSyz,
			reproOpts: reproOpts,
			reproC:    reproC,
		}
		go func() { res <- inst.test() }()
	}
	var errors []error
	for i := 0; i < numVMs; i++ {
		errors = append(errors, <-res)
	}
	return errors, nil
}

type inst struct {
	cfg       *mgrconfig.Config
	reporter  report.Reporter
	vmPool    *vm.Pool
	vm        *vm.Instance
	vmIndex   int
	reproSyz  []byte
	reproOpts []byte
	reproC    []byte
}

func (inst *inst) test() error {
	vmInst, err := inst.vmPool.Create(inst.vmIndex)
	if err != nil {
		testErr := &TestError{
			Boot:  true,
			Title: err.Error(),
		}
		if bootErr, ok := err.(vm.BootErrorer); ok {
			testErr.Title, testErr.Output = bootErr.BootError()
			// This linux-ism avoids detecting any crash during boot as "unexpected kernel reboot".
			output := testErr.Output
			if pos := bytes.Index(output, []byte("Booting the kernel.")); pos != -1 {
				output = output[pos+1:]
			}
			testErr.Report = inst.reporter.Parse(output)
			if testErr.Report != nil {
				testErr.Title = testErr.Report.Title
			} else {
				testErr.Report = &report.Report{
					Title:  testErr.Title,
					Output: testErr.Output,
				}
			}
			if err := inst.reporter.Symbolize(testErr.Report); err != nil {
				// TODO(dvyukov): send such errors to dashboard.
				log.Logf(0, "failed to symbolize report: %v", err)
			}
		}
		return testErr
	}
	defer vmInst.Close()
	inst.vm = vmInst
	if err := inst.testInstance(); err != nil {
		return err
	}
	if len(inst.reproSyz) != 0 {
		if err := inst.testRepro(); err != nil {
			return err
		}
	}
	return nil
}

// testInstance tests basic operation of the provided VM
// (that we can copy binaries, run binaries, they can connect to host, run syzkaller programs, etc).
// TestError is returned if there is a problem with the kernel (e.g. crash).
func (inst *inst) testInstance() error {
	ln, err := net.Listen("tcp", ":")
	if err != nil {
		return fmt.Errorf("failed to open listening socket: %v", err)
	}
	defer ln.Close()
	var gotConn uint32
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			atomic.StoreUint32(&gotConn, 1)
		}
	}()
	fwdAddr, err := inst.vm.Forward(ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		return fmt.Errorf("failed to setup port forwarding: %v", err)
	}
	fuzzerBin, err := inst.vm.Copy(inst.cfg.SyzFuzzerBin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	executorBin, err := inst.vm.Copy(inst.cfg.SyzExecutorBin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	cmd := fmt.Sprintf("%v -test -executor=%v -name=test -arch=%v -manager=%v -cover=0 -sandbox=%v",
		fuzzerBin, executorBin, inst.cfg.TargetArch, fwdAddr, inst.cfg.Sandbox)
	outc, errc, err := inst.vm.Run(5*time.Minute, nil, cmd)
	if err != nil {
		return fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := vm.MonitorExecution(outc, errc, inst.reporter, true)
	if rep != nil {
		if err := inst.reporter.Symbolize(rep); err != nil {
			// TODO(dvyukov): send such errors to dashboard.
			log.Logf(0, "failed to symbolize report: %v", err)
		}
		return &TestError{
			Title:  rep.Title,
			Report: rep,
		}
	}
	if atomic.LoadUint32(&gotConn) == 0 {
		return fmt.Errorf("test machine failed to connect to host")
	}
	return nil
}

func (inst *inst) testRepro() error {
	cfg := inst.cfg
	execprogBin, err := inst.vm.Copy(cfg.SyzExecprogBin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	executorBin, err := inst.vm.Copy(cfg.SyzExecutorBin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	progFile := filepath.Join(cfg.Workdir, "repro.prog")
	if err := osutil.WriteFile(progFile, inst.reproSyz); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}
	vmProgFile, err := inst.vm.Copy(progFile)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	opts, err := csource.DeserializeOptions(inst.reproOpts)
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
		execprogBin, executorBin, cfg.TargetArch, cfg.Procs, opts.Sandbox,
		opts.FaultCall, opts.FaultNth, vmProgFile)
	if err := inst.testProgram(cmdSyz, 7*time.Minute); err != nil {
		return err
	}
	if len(inst.reproC) == 0 {
		return nil
	}
	cFile := filepath.Join(cfg.Workdir, "repro.c")
	if err := osutil.WriteFile(cFile, inst.reproC); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return err
	}
	bin, err := csource.Build(target, "c", cFile)
	if err != nil {
		return err
	}
	vmBin, err := inst.vm.Copy(bin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	// We should test for longer (e.g. 5 mins), but the problem is that
	// reproducer does not print anything, so after 3 mins we detect "no output".
	return inst.testProgram(vmBin, time.Minute)
}

func (inst *inst) testProgram(command string, testTime time.Duration) error {
	outc, errc, err := inst.vm.Run(testTime, nil, command)
	if err != nil {
		return fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := vm.MonitorExecution(outc, errc, inst.reporter, true)
	if rep == nil {
		return nil
	}
	if err := inst.reporter.Symbolize(rep); err != nil {
		log.Logf(0, "failed to symbolize report: %v", err)
	}
	return &CrashError{Report: rep}
}
