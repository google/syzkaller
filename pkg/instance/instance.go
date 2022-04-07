// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package instance provides helper functions for creation of temporal instances
// used for testing of images, patches and bisection.
package instance

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

type Env interface {
	BuildSyzkaller(string, string) error
	BuildKernel(string, string, string, string, string, []byte) (string, build.ImageDetails, error)
	Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error)
}

type env struct {
	cfg           *mgrconfig.Config
	optionalFlags bool
}

func NewEnv(cfg *mgrconfig.Config) (Env, error) {
	if !vm.AllowsOvercommit(cfg.Type) {
		return nil, fmt.Errorf("test instances are not supported for %v VMs", cfg.Type)
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
	env := &env{
		cfg:           cfg,
		optionalFlags: true,
	}
	return env, nil
}

func (env *env) BuildSyzkaller(repoURL, commit string) error {
	cfg := env.cfg
	srcIndex := strings.LastIndex(cfg.Syzkaller, "/src/")
	if srcIndex == -1 {
		return fmt.Errorf("syzkaller path %q is not in GOPATH", cfg.Syzkaller)
	}
	repo := vcs.NewSyzkallerRepo(cfg.Syzkaller)
	if _, err := repo.CheckoutCommit(repoURL, commit); err != nil {
		return fmt.Errorf("failed to checkout syzkaller repo: %v", err)
	}
	// The following commit ("syz-fuzzer: support optional flags") adds support for optional flags
	// in syz-fuzzer and syz-execprog. This is required to invoke older binaries with newer flags
	// without failing due to unknown flags.
	optionalFlags, err := repo.Contains("64435345f0891706a7e0c7885f5f7487581e6005")
	if err != nil {
		return fmt.Errorf("optional flags check failed: %v", err)
	}
	env.optionalFlags = optionalFlags
	cmd := osutil.Command(MakeBin, "target")
	cmd.Dir = cfg.Syzkaller
	goEnvOptions := []string{
		"GOPATH=" + cfg.Syzkaller[:srcIndex],
		"GO111MODULE=auto",
	}
	cmd.Env = append(append([]string{}, os.Environ()...), goEnvOptions...)
	cmd.Env = append(cmd.Env,
		"TARGETOS="+cfg.TargetOS,
		"TARGETVMARCH="+cfg.TargetVMArch,
		"TARGETARCH="+cfg.TargetArch,
		// Since we can be building very old revisions for bisection here,
		// make the build as permissive as possible.
		// Newer compilers tend to produce more warnings also kernel headers may be broken, e.g.:
		// ebtables.h:197:19: error: invalid conversion from ‘void*’ to ‘ebt_entry_target*’
		"CFLAGS=-fpermissive -w",
	)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		goEnvCmd := osutil.Command("go", "env")
		goEnvCmd.Dir = cfg.Syzkaller
		goEnvCmd.Env = append(append([]string{}, os.Environ()...), goEnvOptions...)
		goEnvOut, goEnvErr := osutil.Run(time.Hour, goEnvCmd)
		gitStatusOut, gitStatusErr := osutil.RunCmd(time.Hour, cfg.Syzkaller, "git", "status")
		return fmt.Errorf("syzkaller build failed: %v\ngo env (err=%v)\n%s\ngit status (err=%v)\n%s",
			err, goEnvErr, goEnvOut, gitStatusErr, gitStatusOut)
	}
	return nil
}

func (env *env) BuildKernel(compilerBin, ccacheBin, userspaceDir, cmdlineFile, sysctlFile string, kernelConfig []byte) (
	string, build.ImageDetails, error) {
	imageDir := filepath.Join(env.cfg.Workdir, "image")
	params := build.Params{
		TargetOS:     env.cfg.TargetOS,
		TargetArch:   env.cfg.TargetVMArch,
		VMType:       env.cfg.Type,
		KernelDir:    env.cfg.KernelSrc,
		OutputDir:    imageDir,
		Compiler:     compilerBin,
		Ccache:       ccacheBin,
		UserspaceDir: userspaceDir,
		CmdlineFile:  cmdlineFile,
		SysctlFile:   sysctlFile,
		Config:       kernelConfig,
	}
	details, err := build.Image(params)
	if err != nil {
		return "", details, err
	}
	if err := SetConfigImage(env.cfg, imageDir, true); err != nil {
		return "", details, err
	}
	kernelConfigFile := filepath.Join(imageDir, "kernel.config")
	if !osutil.IsExist(kernelConfigFile) {
		kernelConfigFile = ""
	}
	return kernelConfigFile, details, nil
}

func SetConfigImage(cfg *mgrconfig.Config, imageDir string, reliable bool) error {
	cfg.KernelObj = filepath.Join(imageDir, "obj")
	cfg.Image = filepath.Join(imageDir, "image")
	if keyFile := filepath.Join(imageDir, "key"); osutil.IsExist(keyFile) {
		cfg.SSHKey = keyFile
	}
	vmConfig := make(map[string]interface{})
	if err := json.Unmarshal(cfg.VM, &vmConfig); err != nil {
		return fmt.Errorf("failed to parse VM config: %v", err)
	}
	if cfg.Type == "qemu" || cfg.Type == "vmm" {
		if kernel := filepath.Join(imageDir, "kernel"); osutil.IsExist(kernel) {
			vmConfig["kernel"] = kernel
		}
		if initrd := filepath.Join(imageDir, "initrd"); osutil.IsExist(initrd) {
			vmConfig["initrd"] = initrd
		}
	}
	if cfg.Type == "gce" {
		// Don't use preemptible VMs for image testing, patch testing and bisection.
		vmConfig["preemptible"] = !reliable
	}
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize VM config: %v", err)
	}
	cfg.VM = vmCfg
	return nil
}

func OverrideVMCount(cfg *mgrconfig.Config, n int) error {
	vmConfig := make(map[string]interface{})
	if err := json.Unmarshal(cfg.VM, &vmConfig); err != nil {
		return fmt.Errorf("failed to parse VM config: %v", err)
	}
	if vmConfig["count"] == nil || !vm.AllowsOvercommit(cfg.Type) {
		return nil
	}
	vmConfig["count"] = n
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize VM config: %v", err)
	}
	cfg.VM = vmCfg
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
func (env *env) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	if err := mgrconfig.Complete(env.cfg); err != nil {
		return nil, err
	}
	reporter, err := report.NewReporter(env.cfg)
	if err != nil {
		return nil, err
	}
	vmPool, err := vm.Create(env.cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %v", err)
	}
	if n := vmPool.Count(); numVMs > n {
		numVMs = n
	}
	res := make(chan error, numVMs)
	for i := 0; i < numVMs; i++ {
		inst := &inst{
			cfg:           env.cfg,
			optionalFlags: env.optionalFlags,
			reporter:      reporter,
			vmPool:        vmPool,
			vmIndex:       i,
			reproSyz:      reproSyz,
			reproOpts:     reproOpts,
			reproC:        reproC,
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
	cfg           *mgrconfig.Config
	optionalFlags bool
	reporter      *report.Reporter
	vmPool        *vm.Pool
	vm            *vm.Instance
	vmIndex       int
	reproSyz      []byte
	reproOpts     []byte
	reproC        []byte
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
			rep := inst.reporter.Parse(testErr.Output)
			if rep != nil && rep.Type == report.UnexpectedReboot {
				// Avoid detecting any boot crash as "unexpected kernel reboot".
				rep = inst.reporter.ParseFrom(testErr.Output, rep.SkipPos)
			}
			if rep == nil {
				rep = &report.Report{
					Title:  testErr.Title,
					Output: testErr.Output,
				}
			}
			if err := inst.reporter.Symbolize(rep); err != nil {
				// TODO(dvyukov): send such errors to dashboard.
				log.Logf(0, "failed to symbolize report: %v", err)
			}
			testErr.Report = rep
			testErr.Title = rep.Title
		}
		return testErr
	}
	defer vmInst.Close()
	inst.vm = vmInst
	if err := inst.testInstance(); err != nil {
		return err
	}
	if len(inst.reproSyz) != 0 || len(inst.reproC) != 0 {
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
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		acceptErr <- err
	}()
	fwdAddr, err := inst.vm.Forward(ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		return fmt.Errorf("failed to setup port forwarding: %v", err)
	}

	fuzzerBin, err := inst.vm.Copy(inst.cfg.FuzzerBin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := inst.cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.vm.Copy(inst.cfg.ExecutorBin)
		if err != nil {
			return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
		}
	}

	cmd := OldFuzzerCmd(fuzzerBin, executorBin, targets.TestOS, inst.cfg.TargetOS, inst.cfg.TargetArch, fwdAddr,
		inst.cfg.Sandbox, 0, inst.cfg.Cover, true, inst.optionalFlags, inst.cfg.Timeouts.Slowdown)
	outc, errc, err := inst.vm.Run(10*time.Minute*inst.cfg.Timeouts.Scale, nil, cmd)
	if err != nil {
		return fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := inst.vm.MonitorExecution(outc, errc, inst.reporter, vm.ExitNormal)
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
	select {
	case err := <-acceptErr:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("test machine failed to connect to host")
	}
}

func (inst *inst) testRepro() error {
	cfg := inst.cfg
	if len(inst.reproSyz) > 0 {
		execprogBin, err := inst.vm.Copy(cfg.ExecprogBin)
		if err != nil {
			return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
		}
		// If ExecutorBin is provided, it means that syz-executor is already in the image,
		// so no need to copy it.
		executorBin := cfg.SysTarget.ExecutorBin
		if executorBin == "" {
			executorBin, err = inst.vm.Copy(inst.cfg.ExecutorBin)
			if err != nil {
				return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
			}
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
		cmdSyz := ExecprogCmd(execprogBin, executorBin, cfg.TargetOS, cfg.TargetArch, opts.Sandbox,
			true, true, true, cfg.Procs, opts.FaultCall, opts.FaultNth, inst.optionalFlags,
			cfg.Timeouts.Slowdown, vmProgFile)
		if err := inst.testProgram(cmdSyz, cfg.Timeouts.NoOutputRunningTime); err != nil {
			return err
		}
	}
	if len(inst.reproC) == 0 {
		return nil
	}
	bin, err := csource.BuildNoWarn(cfg.Target, inst.reproC)
	if err != nil {
		return err
	}
	defer os.Remove(bin)
	vmBin, err := inst.vm.Copy(bin)
	if err != nil {
		return &TestError{Title: fmt.Sprintf("failed to copy test binary to VM: %v", err)}
	}
	// We should test for more than full "no output" timeout, but the problem is that C reproducers
	// don't print anything, so we will get a false "no output" crash.
	return inst.testProgram(vmBin, cfg.Timeouts.NoOutput/2)
}

func (inst *inst) testProgram(command string, testTime time.Duration) error {
	outc, errc, err := inst.vm.Run(testTime, nil, command)
	if err != nil {
		return fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := inst.vm.MonitorExecution(outc, errc, inst.reporter,
		vm.ExitTimeout|vm.ExitNormal|vm.ExitError)
	if rep == nil {
		return nil
	}
	if err := inst.reporter.Symbolize(rep); err != nil {
		log.Logf(0, "failed to symbolize report: %v", err)
	}
	return &CrashError{Report: rep}
}

type FuzzerCmdArgs struct {
	Fuzzer    string
	Executor  string
	Name      string
	OS        string
	Arch      string
	FwdAddr   string
	Sandbox   string
	Procs     int
	Verbosity int
	Cover     bool
	Debug     bool
	Test      bool
	Runtest   bool
	Slowdown  int
	RawCover  bool
}

func FuzzerCmd(args *FuzzerCmdArgs) string {
	osArg := ""
	if targets.Get(args.OS, args.Arch).HostFuzzer {
		// Only these OSes need the flag, because the rest assume host OS.
		// But speciying OS for all OSes breaks patch testing on syzbot
		// because old execprog does not have os flag.
		osArg = " -os=" + args.OS
	}
	runtestArg := ""
	if args.Runtest {
		runtestArg = " -runtest"
	}
	verbosityArg := ""
	if args.Verbosity != 0 {
		verbosityArg = fmt.Sprintf(" -vv=%v", args.Verbosity)
	}
	flags := []tool.Flag{}
	if args.Slowdown > 0 {
		flags = append(flags, tool.Flag{Name: "slowdown", Value: fmt.Sprint(args.Slowdown)})
	}
	if args.RawCover {
		flags = append(flags, tool.Flag{Name: "raw_cover", Value: "true"})
	}
	optionalArg := ""
	if len(flags) > 0 {
		optionalArg += " " + tool.OptionalFlags(flags)
	}
	return fmt.Sprintf("%v -executor=%v -name=%v -arch=%v%v -manager=%v -sandbox=%v"+
		" -procs=%v -cover=%v -debug=%v -test=%v%v%v%v",
		args.Fuzzer, args.Executor, args.Name, args.Arch, osArg, args.FwdAddr, args.Sandbox,
		args.Procs, args.Cover, args.Debug, args.Test, runtestArg, verbosityArg, optionalArg)
}

func OldFuzzerCmd(fuzzer, executor, name, OS, arch, fwdAddr, sandbox string, procs int,
	cover, test, optionalFlags bool, slowdown int) string {
	return FuzzerCmd(&FuzzerCmdArgs{Fuzzer: fuzzer, Executor: executor, Name: name,
		OS: OS, Arch: arch, FwdAddr: fwdAddr, Sandbox: sandbox, Procs: procs,
		Verbosity: 0, Cover: cover, Debug: false, Test: test, Runtest: false,
		Slowdown: slowdown})
}

func ExecprogCmd(execprog, executor, OS, arch, sandbox string, repeat, threaded, collide bool,
	procs, faultCall, faultNth int, optionalFlags bool, slowdown int, progFile string) string {
	repeatCount := 1
	if repeat {
		repeatCount = 0
	}
	osArg := ""
	if targets.Get(OS, arch).HostFuzzer {
		osArg = " -os=" + OS
	}
	optionalArg := ""

	if faultCall >= 0 {
		optionalArg = fmt.Sprintf(" -fault_call=%v -fault_nth=%v",
			faultCall, faultNth)
	}

	if optionalFlags {
		optionalArg += " " + tool.OptionalFlags([]tool.Flag{
			{Name: "slowdown", Value: fmt.Sprint(slowdown)},
		})
	}

	return fmt.Sprintf("%v -executor=%v -arch=%v%v -sandbox=%v"+
		" -procs=%v -repeat=%v -threaded=%v -collide=%v -cover=0%v %v",
		execprog, executor, arch, osArg, sandbox,
		procs, repeatCount, threaded, collide,
		optionalArg, progFile)
}

var MakeBin = func() string {
	if runtime.GOOS == targets.FreeBSD || runtime.GOOS == targets.OpenBSD {
		return "gmake"
	}
	return "make"
}()

func RunnerCmd(prog, fwdAddr, os, arch string, poolIdx, vmIdx int, threaded, newEnv bool) string {
	return fmt.Sprintf("%s -addr=%s -os=%s -arch=%s -pool=%d -vm=%d "+
		"-threaded=%t -new-env=%t", prog, fwdAddr, os, arch, poolIdx, vmIdx, threaded, newEnv)
}
