// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

type ExecutorLogger func(int, string, ...interface{})

type OptionalConfig struct {
	Logf               ExecutorLogger
	OldFlagsCompatMode bool
	BeforeContextLen   int
	StraceBin          string
}

type ExecProgInstance struct {
	execprogBin string
	executorBin string
	reporter    *report.Reporter
	mgrCfg      *mgrconfig.Config
	VMInstance  *vm.Instance
	OptionalConfig
}

type RunResult struct {
	Output   []byte
	Report   *report.Report
	Duration time.Duration
}

const (
	// It's reasonable to expect that tools/syz-execprog should not normally
	// return a non-zero exit code.
	SyzExitConditions = vm.ExitTimeout | vm.ExitNormal
	binExitConditions = vm.ExitTimeout | vm.ExitNormal | vm.ExitError
)

func SetupExecProg(vmInst *vm.Instance, mgrCfg *mgrconfig.Config, reporter *report.Reporter,
	opt *OptionalConfig) (*ExecProgInstance, error) {
	var err error
	execprogBin := mgrCfg.SysTarget.ExecprogBin
	if execprogBin == "" {
		execprogBin, err = vmInst.Copy(mgrCfg.ExecprogBin)
		if err != nil {
			return nil, &TestError{Title: fmt.Sprintf("failed to copy syz-execprog to VM: %v", err)}
		}
	}
	executorBin := mgrCfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = vmInst.Copy(mgrCfg.ExecutorBin)
		if err != nil {
			return nil, &TestError{Title: fmt.Sprintf("failed to copy syz-executor to VM: %v", err)}
		}
	}
	ret := &ExecProgInstance{
		execprogBin: execprogBin,
		executorBin: executorBin,
		reporter:    reporter,
		mgrCfg:      mgrCfg,
		VMInstance:  vmInst,
	}
	if opt != nil {
		ret.OptionalConfig = *opt
		if !mgrCfg.StraceBinOnTarget && ret.StraceBin != "" {
			var err error
			ret.StraceBin, err = vmInst.Copy(ret.StraceBin)
			if err != nil {
				return nil, &TestError{Title: fmt.Sprintf("failed to copy strace bin: %v", err)}
			}
		}
	}
	if ret.Logf == nil {
		ret.Logf = func(int, string, ...interface{}) {}
	}
	return ret, nil
}

func CreateExecProgInstance(vmPool *vm.Pool, vmIndex int, mgrCfg *mgrconfig.Config,
	reporter *report.Reporter, opt *OptionalConfig) (*ExecProgInstance, error) {
	vmInst, err := vmPool.Create(vmIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}
	ret, err := SetupExecProg(vmInst, mgrCfg, reporter, opt)
	if err != nil {
		vmInst.Close()
		return nil, err
	}
	return ret, nil
}

func (inst *ExecProgInstance) runCommand(command string, duration time.Duration,
	exitCondition vm.ExitCondition) (*RunResult, error) {
	start := time.Now()

	var prefixOutput []byte
	if inst.StraceBin != "" {
		filterCalls := ""
		switch inst.mgrCfg.SysTarget.OS {
		case targets.Linux:
			// wait4 and nanosleep generate a lot of noise, especially when running syz-executor.
			// We cut them on the VM side in order to decrease load on the network and to use
			// the limited buffer size wisely.
			filterCalls = ` -e \!wait4,clock_nanosleep,nanosleep`
		}
		command = inst.StraceBin + filterCalls + ` -s 100 -x -f ` + command
		prefixOutput = []byte(fmt.Sprintf("%s\n\n<...>\n", command))
	}
	opts := []any{exitCondition}
	if inst.BeforeContextLen != 0 {
		opts = append(opts, vm.OutputSize(inst.BeforeContextLen))
	}
	output, rep, err := inst.VMInstance.Run(duration, inst.reporter, command, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to run command in VM: %w", err)
	}
	if rep == nil {
		inst.Logf(2, "program did not crash")
	} else {
		if err := inst.reporter.Symbolize(rep); err != nil {
			inst.Logf(0, "failed to symbolize report: %v", err)
		}
		inst.Logf(2, "program crashed: %v", rep.Title)
	}
	return &RunResult{
		Output:   append(prefixOutput, output...),
		Report:   rep,
		Duration: time.Since(start),
	}, nil
}

func (inst *ExecProgInstance) runBinary(bin string, duration time.Duration) (*RunResult, error) {
	bin, err := inst.VMInstance.Copy(bin)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy binary to VM: %v", err)}
	}
	return inst.runCommand(bin, duration, binExitConditions)
}

type ExecParams struct {
	// Only one of these will be used, depending on the function.
	CProg   *prog.Prog
	SyzProg []byte

	Opts     csource.Options
	Duration time.Duration
	// If ExitConditions is empty, RunSyzProg() will assume instance.SyzExitConditions.
	// RunCProg() always runs with binExitConditions.
	ExitConditions vm.ExitCondition
}

func (inst *ExecProgInstance) RunCProg(params ExecParams) (*RunResult, error) {
	src, err := csource.Write(params.CProg, params.Opts)
	if err != nil {
		return nil, err
	}
	inst.Logf(2, "testing compiled C program (duration=%v, %+v): %s",
		params.Duration, params.Opts, params.CProg)
	return inst.RunCProgRaw(src, params.CProg.Target, params.Duration)
}

func (inst *ExecProgInstance) RunCProgRaw(src []byte, target *prog.Target,
	duration time.Duration) (*RunResult, error) {
	bin, err := csource.BuildNoWarn(target, src)
	if err != nil {
		return nil, err
	}
	defer os.Remove(bin)
	return inst.runBinary(bin, duration)
}

func (inst *ExecProgInstance) RunSyzProgFile(progFile string, duration time.Duration,
	opts csource.Options, exitCondition vm.ExitCondition) (*RunResult, error) {
	vmProgFile, err := inst.VMInstance.Copy(progFile)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy prog to VM: %v", err)}
	}
	target := inst.mgrCfg.SysTarget
	command := ExecprogCmd(inst.execprogBin, inst.executorBin, target.OS, target.Arch, inst.mgrCfg.Type, opts,
		!inst.OldFlagsCompatMode, inst.mgrCfg.Timeouts.Slowdown, vmProgFile)
	return inst.runCommand(command, duration, exitCondition)
}

func (inst *ExecProgInstance) RunSyzProg(params ExecParams) (*RunResult, error) {
	progFile, err := osutil.WriteTempFile(params.SyzProg)
	if err != nil {
		return nil, err
	}
	defer os.Remove(progFile)

	if params.ExitConditions == 0 {
		params.ExitConditions = SyzExitConditions
	}
	return inst.RunSyzProgFile(progFile, params.Duration, params.Opts, params.ExitConditions)
}
