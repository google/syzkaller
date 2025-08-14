// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package instance provides helper functions for creation of temporal instances
// used for testing of images, patches and bisection.
package instance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

type Env interface {
	BuildSyzkaller(string, string) (string, error)
	CleanKernel(*BuildKernelConfig) error
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
	MakeBin      string
	CompilerBin  string
	LinkerBin    string
	CcacheBin    string
	UserspaceDir string
	CmdlineFile  string
	SysctlFile   string
	KernelConfig []byte
	BuildCPUs    int
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
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
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
		return "", fmt.Errorf("failed to checkout syzkaller repo: %w", err)
	}
	// The following commit ("syz-fuzzer: support optional flags") adds support for optional flags
	// in syz-execprog. This is required to invoke older binaries with newer flags
	// without failing due to unknown flags.
	optionalFlags, err := repo.Contains("64435345f0891706a7e0c7885f5f7487581e6005")
	if err != nil {
		return "", fmt.Errorf("optional flags check failed: %w", err)
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
		return buildLog, fmt.Errorf("syzkaller build failed: %w\n%s", buildErr, buildLog)
	}
	return buildLog, nil
}

func (env *env) buildParamsFromCfg(buildCfg *BuildKernelConfig) build.Params {
	return build.Params{
		TargetOS:     env.cfg.TargetOS,
		TargetArch:   env.cfg.TargetVMArch,
		VMType:       env.cfg.Type,
		KernelDir:    env.cfg.KernelSrc,
		OutputDir:    filepath.Join(env.cfg.Workdir, "image"),
		Make:         buildCfg.MakeBin,
		Compiler:     buildCfg.CompilerBin,
		Linker:       buildCfg.LinkerBin,
		Ccache:       buildCfg.CcacheBin,
		UserspaceDir: buildCfg.UserspaceDir,
		CmdlineFile:  buildCfg.CmdlineFile,
		SysctlFile:   buildCfg.SysctlFile,
		Config:       buildCfg.KernelConfig,
		BuildCPUs:    buildCfg.BuildCPUs,
	}
}

func (env *env) BuildKernel(buildCfg *BuildKernelConfig) (
	string, build.ImageDetails, error) {
	if env.buildSem != nil {
		env.buildSem.Wait()
		defer env.buildSem.Signal()
	}
	params := env.buildParamsFromCfg(buildCfg)
	details, err := build.Image(params)
	if err != nil {
		return "", details, err
	}
	if err := SetConfigImage(env.cfg, params.OutputDir, true); err != nil {
		return "", details, err
	}
	kernelConfigFile := filepath.Join(params.OutputDir, "kernel.config")
	if !osutil.IsExist(kernelConfigFile) {
		kernelConfigFile = ""
	}
	return kernelConfigFile, details, nil
}

func (env *env) CleanKernel(buildCfg *BuildKernelConfig) error {
	if env.buildSem != nil {
		env.buildSem.Wait()
		defer env.buildSem.Signal()
	}
	params := env.buildParamsFromCfg(buildCfg)
	return build.Clean(params)
}

func SetConfigImage(cfg *mgrconfig.Config, imageDir string, reliable bool) error {
	cfg.KernelObj = filepath.Join(imageDir, "obj")
	cfg.Image = filepath.Join(imageDir, "image")
	if keyFile := filepath.Join(imageDir, "key"); osutil.IsExist(keyFile) {
		cfg.SSHKey = keyFile
	}
	vmConfig := make(map[string]interface{})
	if err := json.Unmarshal(cfg.VM, &vmConfig); err != nil {
		return fmt.Errorf("failed to parse VM config: %w", err)
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
		return fmt.Errorf("failed to serialize VM config: %w", err)
	}
	cfg.VM = vmCfg
	return nil
}

func OverrideVMCount(cfg *mgrconfig.Config, n int) error {
	vmConfig := make(map[string]interface{})
	if err := json.Unmarshal(cfg.VM, &vmConfig); err != nil {
		return fmt.Errorf("failed to parse VM config: %w", err)
	}
	if vmConfig["count"] == nil || !vm.AllowsOvercommit(cfg.Type) {
		return nil
	}
	vmConfig["count"] = n
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize VM config: %w", err)
	}
	cfg.VM = vmCfg
	cfg.FuzzingVMs = min(cfg.FuzzingVMs, n)
	return nil
}

type TestError struct {
	Boot   bool // says if the error happened during booting or during instance testing
	Infra  bool // whether the problem is related to some infrastructure problems
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
		return nil, fmt.Errorf("failed to create VM pool: %w", err)
	}
	defer vmPool.Close()
	numVMs = min(numVMs, vmPool.Count())
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
		var bootErr vm.BootErrorer
		if errors.As(err, &bootErr) {
			testErr.Title, testErr.Output = bootErr.BootError()
			ret.RawOutput = testErr.Output
			rep := inst.reporter.Parse(testErr.Output)
			if rep != nil && rep.Type == crash.UnexpectedReboot {
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
		} else {
			testErr.Infra = true
			var infraErr vm.InfraErrorer
			if errors.As(err, &infraErr) {
				// In case there's more info available.
				testErr.Title, testErr.Output = infraErr.InfraError()
			}
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

// testInstance tests that the VM does not crash on a simple program.
// TestError is returned if there is a problem with the kernel (e.g. crash).
func (inst *inst) testInstance() error {
	execProg, err := SetupExecProg(inst.vm, inst.cfg, inst.reporter, &OptionalConfig{
		OldFlagsCompatMode: !inst.optionalFlags,
	})
	if err != nil {
		return err
	}
	// Note: we create the test program on a newer syzkaller revision and pass it to the old execprog.
	// We rely on the non-strict program parsing to parse it successfully.
	testProg := inst.cfg.Target.DataMmapProg().Serialize()
	// Use the same options as the target reproducer.
	// E.g. if it does not use wifi, we won't test it, which reduces changes of unrelated kernel bugs.
	// Note: we keep fault injection if it's enabled in the reproducer to test that fault injection works
	// (does not produce some kernel oops when activated).
	opts, err := inst.csourceOptions()
	if err != nil {
		return err
	}
	opts.Repeat = false
	out, err := execProg.RunSyzProg(ExecParams{
		SyzProg:        testProg,
		Duration:       inst.cfg.Timeouts.NoOutputRunningTime,
		Opts:           opts,
		ExitConditions: vm.ExitNormal,
	})
	if err != nil {
		return &TestError{Title: err.Error()}
	}
	if out.Report != nil {
		return &TestError{Title: out.Report.Title, Report: out.Report}
	}
	return nil
}

func (inst *inst) testRepro() ([]byte, error) {
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
			return res.Output, &CrashError{Report: res.Report}
		}
		return res.Output, nil
	}
	out := []byte{}
	if len(inst.reproSyz) > 0 {
		opts, err := inst.csourceOptions()
		if err != nil {
			return nil, err
		}
		out, err = transformError(execProg.RunSyzProg(ExecParams{
			SyzProg:  inst.reproSyz,
			Duration: inst.cfg.Timeouts.NoOutputRunningTime,
			Opts:     opts,
		}))
		if err != nil {
			return out, err
		}
	}
	if len(inst.reproC) > 0 {
		// We should test for more than full "no output" timeout, but the problem is that C reproducers
		// don't print anything, so we will get a false "no output" crash.
		out, err = transformError(execProg.RunCProgRaw(inst.reproC, inst.cfg.Target,
			inst.cfg.Timeouts.NoOutput/2))
	}
	return out, err
}

func (inst *inst) csourceOptions() (csource.Options, error) {
	if len(inst.reproSyz) == 0 {
		// If no syz repro is provided, the functionality is likely being used to test
		// for the crashes that don't need a reproducer (e.g. kernel build/boot/test errors).
		// Use the default options, that's the best we can do.
		return csource.DefaultOpts(inst.cfg), nil
	}
	opts, err := csource.DeserializeOptions(inst.reproOpts)
	if err != nil {
		return opts, err
	}
	// Combine repro options and default options in a way that increases chances to reproduce the crash.
	// We always enable threaded/collide as it should be [almost] strictly better.
	opts.Repeat, opts.Threaded = true, true
	return opts, nil
}

// nolint:revive
func ExecprogCmd(execprog, executor, OS, arch, vmType string, opts csource.Options,
	optionalFlags bool, slowdown int, progFile string) string {
	repeatCount := 1
	if opts.Repeat {
		repeatCount = 0
	}
	sandbox := opts.Sandbox
	if sandbox == "" {
		// Executor does not support empty sandbox, so we use none instead.
		sandbox = "none"
	}
	osArg := ""
	if targets.Get(OS, arch).HostFuzzer {
		osArg = " -os=" + OS
	}
	optionalArg := ""
	if opts.Fault && opts.FaultCall >= 0 {
		optionalArg = fmt.Sprintf(" -fault_call=%v -fault_nth=%v",
			opts.FaultCall, opts.FaultNth)
	}
	if optionalFlags {
		optionalArg += " " + tool.OptionalFlags([]tool.Flag{
			{Name: "slowdown", Value: fmt.Sprint(slowdown)},
			{Name: "sandboxArg", Value: fmt.Sprint(opts.SandboxArg)},
			{Name: "type", Value: fmt.Sprint(vmType)},
			{Name: "restart_freq", Value: fmt.Sprint(opts.ProcRestartFreq)},
		})
	}
	return fmt.Sprintf("%v -executor=%v -arch=%v%v -sandbox=%v"+
		" -procs=%v -repeat=%v -threaded=%v -collide=%v -cover=0%v %v",
		execprog, executor, arch, osArg, sandbox,
		opts.Procs, repeatCount, opts.Threaded, opts.Collide,
		optionalArg, progFile)
}

var MakeBin = func() string {
	if runtime.GOOS == targets.FreeBSD || runtime.GOOS == targets.OpenBSD {
		return "gmake"
	}
	return "make"
}()

// nolint:revive
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

// RunSmokeTest executes syz-manager in the smoke test mode and returns two values:
// The crash report, if the testing failed.
// An error if there was a problem not related to testing the kernel.
func RunSmokeTest(cfg *mgrconfig.Config) (*report.Report, error) {
	if !vm.AllowsOvercommit(cfg.Type) {
		return nil, nil // No support for creating machines out of thin air.
	}
	osutil.MkdirAll(cfg.Workdir)
	configFile := filepath.Join(cfg.Workdir, "manager.cfg")
	if err := config.SaveFile(configFile, cfg); err != nil {
		return nil, err
	}
	timeout := 30 * time.Minute * cfg.Timeouts.Scale
	bin := filepath.Join(cfg.Syzkaller, "bin", "syz-manager")
	output, retErr := osutil.RunCmd(timeout, "", bin, "-config", configFile, "-mode=smoke-test")
	if retErr == nil {
		return nil, nil
	}
	// If there was a kernel bug, report it to dashboard.
	// Otherwise just save the output in a temp file and log an error, unclear what else we can do.
	reportData, err := os.ReadFile(filepath.Join(cfg.Workdir, "report.json"))
	if err != nil {
		if os.IsNotExist(err) {
			rep := &report.Report{
				Title:  "SYZFATAL: image testing failed w/o kernel bug",
				Output: output,
			}
			return rep, nil
		}
		return nil, err
	}
	rep := new(report.Report)
	if err := json.Unmarshal(reportData, rep); err != nil {
		return nil, fmt.Errorf("failed to unmarshal smoke test report: %w", err)
	}
	return rep, nil
}
