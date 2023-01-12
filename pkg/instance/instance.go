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
	BuildSyzkaller(string, string) (string, error)
	BuildKernel(*BuildKernelConfig) (string, build.ImageDetails, error)
	Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]EnvTestResult, error)
}

type env struct {
	cfg           *mgrconfig.Config
	optionalFlags bool
	buildSem      *Semaphore
	testSem       *Semaphore
}

type BuildKernelConfig struct {
	CompilerBin  string
	LinkerBin    string
	CcacheBin    string
	UserspaceDir string
	CmdlineFile  string
	SysctlFile   string
	KernelConfig []byte
}

func NewEnv(cfg *mgrconfig.Config, buildSem, testSem *Semaphore) (Env, error) {
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
		buildSem:      buildSem,
		testSem:       testSem,
	}
	return env, nil
}

func (env *env) BuildSyzkaller(repoURL, commit string) (string, error) {
	if env.buildSem != nil {
		env.buildSem.Wait()
		defer env.buildSem.Signal()
	}
	cfg := env.cfg
	srcIndex := strings.LastIndex(cfg.Syzkaller, "/src/")
	if srcIndex == -1 {
		return "", fmt.Errorf("syzkaller path %q is not in GOPATH", cfg.Syzkaller)
	}
	repo := vcs.NewSyzkallerRepo(cfg.Syzkaller)
	if _, err := repo.CheckoutCommit(repoURL, commit); err != nil {
		return "", fmt.Errorf("failed to checkout syzkaller repo: %v", err)
	}
	// The following commit ("syz-fuzzer: support optional flags") adds support for optional flags
	// in syz-fuzzer and syz-execprog. This is required to invoke older binaries with newer flags
	// without failing due to unknown flags.
	optionalFlags, err := repo.Contains("64435345f0891706a7e0c7885f5f7487581e6005")
	if err != nil {
		return "", fmt.Errorf("optional flags check failed: %v", err)
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

	// We collect the potentially useful debug info here unconditionally, because we will
	// only figure out later whether we actually need it (e.g. if the patch testing fails).
	goEnvCmd := osutil.Command("go", "env")
	goEnvCmd.Dir = cfg.Syzkaller
	goEnvCmd.Env = append(append([]string{}, os.Environ()...), goEnvOptions...)
	goEnvOut, goEnvErr := osutil.Run(time.Hour, goEnvCmd)
	gitStatusOut, gitStatusErr := osutil.RunCmd(time.Hour, cfg.Syzkaller, "git", "status")
	// Compile syzkaller.
	buildOutput, buildErr := osutil.Run(time.Hour, cmd)
	buildLog := fmt.Sprintf("go env (err=%v)\n%s\ngit status (err=%v)\n%s\n\n%s",
		goEnvErr, goEnvOut, gitStatusErr, gitStatusOut, buildOutput)
	if buildErr != nil {
		return buildLog, fmt.Errorf("syzkaller build failed: %v\n%s", buildErr, buildLog)
	}
	return buildLog, nil
}

func (env *env) BuildKernel(buildCfg *BuildKernelConfig) (
	string, build.ImageDetails, error) {
	if env.buildSem != nil {
		env.buildSem.Wait()
		defer env.buildSem.Signal()
	}
	imageDir := filepath.Join(env.cfg.Workdir, "image")
	params := build.Params{
		TargetOS:     env.cfg.TargetOS,
		TargetArch:   env.cfg.TargetVMArch,
		VMType:       env.cfg.Type,
		KernelDir:    env.cfg.KernelSrc,
		OutputDir:    imageDir,
		Compiler:     buildCfg.CompilerBin,
		Linker:       buildCfg.LinkerBin,
		Ccache:       buildCfg.CcacheBin,
		UserspaceDir: buildCfg.UserspaceDir,
		CmdlineFile:  buildCfg.CmdlineFile,
		SysctlFile:   buildCfg.SysctlFile,
		Config:       buildCfg.KernelConfig,
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
func (env *env) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]EnvTestResult, error) {
	if env.testSem != nil {
		env.testSem.Wait()
		defer env.testSem.Signal()
	}
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
	res := make(chan EnvTestResult, numVMs)
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
	var ret []EnvTestResult
	for i := 0; i < numVMs; i++ {
		ret = append(ret, <-res)
	}
	return ret, nil
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

type EnvTestResult struct {
	Error     error
	RawOutput []byte
}

func (inst *inst) test() EnvTestResult {
	vmInst, err := inst.vmPool.Create(inst.vmIndex)
	if err != nil {
		testErr := &TestError{
			Boot:  true,
			Title: err.Error(),
		}
		ret := EnvTestResult{
			Error: testErr,
		}
		if bootErr, ok := err.(vm.BootErrorer); ok {
			testErr.Title, testErr.Output = bootErr.BootError()
			ret.RawOutput = testErr.Output
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
		return ret
	}
	defer vmInst.Close()
	inst.vm = vmInst
	ret := EnvTestResult{}
	if ret.Error = inst.testInstance(); ret.Error != nil {
		return ret
	}
	if len(inst.reproSyz) != 0 || len(inst.reproC) != 0 {
		ret.RawOutput, ret.Error = inst.testRepro()
	}
	return ret
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
		inst.cfg.Sandbox, inst.cfg.SandboxArg, 0, inst.cfg.Cover, true, inst.optionalFlags, inst.cfg.Timeouts.Slowdown)
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

func (inst *inst) testRepro() ([]byte, error) {
	var err error
	execProg, err := SetupExecProg(inst.vm, inst.cfg, inst.reporter, &OptionalConfig{
		OldFlagsCompatMode: !inst.optionalFlags,
	})
	if err != nil {
		return nil, err
	}
	transformError := func(res *RunResult, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		if res != nil && res.Report != nil {
			return res.RawOutput, &CrashError{Report: res.Report}
		}
		return res.RawOutput, nil
	}
	out := []byte{}
	if len(inst.reproSyz) > 0 {
		var opts csource.Options
		opts, err = csource.DeserializeOptions(inst.reproOpts)
		if err != nil {
			return nil, err
		}
		// Combine repro options and default options in a way that increases chances to reproduce the crash.
		// First, we always enable threaded/collide as it should be [almost] strictly better.
		// Executor does not support empty sandbox, so we use none instead.
		// Finally, always use repeat and multiple procs.
		if opts.Sandbox == "" {
			opts.Sandbox = "none"
		}
		opts.Repeat, opts.Threaded = true, true
		out, err = transformError(execProg.RunSyzProg(inst.reproSyz,
			inst.cfg.Timeouts.NoOutputRunningTime, opts))
	}
	if err == nil && len(inst.reproC) > 0 {
		// We should test for more than full "no output" timeout, but the problem is that C reproducers
		// don't print anything, so we will get a false "no output" crash.
		out, err = transformError(execProg.RunCProgRaw(inst.reproC, inst.cfg.Target,
			inst.cfg.Timeouts.NoOutput/2))
	}
	return out, err
}

type OptionalFuzzerArgs struct {
	Slowdown   int
	RawCover   bool
	SandboxArg int
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
	Optional  *OptionalFuzzerArgs
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
	optionalArg := ""
	if args.Optional != nil {
		flags := []tool.Flag{
			{Name: "slowdown", Value: fmt.Sprint(args.Optional.Slowdown)},
			{Name: "raw_cover", Value: fmt.Sprint(args.Optional.RawCover)},
			{Name: "sandbox_arg", Value: fmt.Sprint(args.Optional.SandboxArg)},
		}
		optionalArg = " " + tool.OptionalFlags(flags)
	}
	return fmt.Sprintf("%v -executor=%v -name=%v -arch=%v%v -manager=%v -sandbox=%v"+
		" -procs=%v -cover=%v -debug=%v -test=%v%v%v%v",
		args.Fuzzer, args.Executor, args.Name, args.Arch, osArg, args.FwdAddr, args.Sandbox,
		args.Procs, args.Cover, args.Debug, args.Test, runtestArg, verbosityArg, optionalArg)
}

func OldFuzzerCmd(fuzzer, executor, name, OS, arch, fwdAddr, sandbox string, sandboxArg, procs int,
	cover, test, optionalFlags bool, slowdown int) string {
	var optional *OptionalFuzzerArgs
	if optionalFlags {
		optional = &OptionalFuzzerArgs{Slowdown: slowdown, SandboxArg: sandboxArg}
	}
	return FuzzerCmd(&FuzzerCmdArgs{Fuzzer: fuzzer, Executor: executor, Name: name,
		OS: OS, Arch: arch, FwdAddr: fwdAddr, Sandbox: sandbox,
		Procs: procs, Verbosity: 0, Cover: cover, Debug: false, Test: test, Runtest: false,
		Optional: optional})
}

func ExecprogCmd(execprog, executor, OS, arch, sandbox string, sandboxArg int, repeat, threaded, collide bool,
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
			{Name: "sandboxArg", Value: fmt.Sprint(sandboxArg)},
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

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(count int) *Semaphore {
	s := &Semaphore{
		ch: make(chan struct{}, count),
	}
	for i := 0; i < count; i++ {
		s.Signal()
	}
	return s
}

func (s *Semaphore) Wait() {
	<-s.ch
}

func (s *Semaphore) WaitC() <-chan struct{} {
	return s.ch
}

func (s *Semaphore) Available() int {
	return len(s.ch)
}

func (s *Semaphore) Signal() {
	if av := s.Available(); av == cap(s.ch) {
		// Not super reliable, but let it be here just in case.
		panic(fmt.Sprintf("semaphore capacity (%d) is exceeded (%d)", cap(s.ch), av))
	}
	s.ch <- struct{}{}
}
