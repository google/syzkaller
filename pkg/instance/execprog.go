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
	ExitCondition      vm.ExitCondition
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
	vm.ExecutionResult
}

func SetupExecProg(vmInst *vm.Instance, mgrCfg *mgrconfig.Config, reporter *report.Reporter,
	opt *OptionalConfig) (*ExecProgInstance, error) {
	execprogBin, err := vmInst.Copy(mgrCfg.ExecprogBin)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy syz-execprog to VM: %v", err)}
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
		if ret.StraceBin != "" {
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
	if ret.ExitCondition == 0 {
		ret.ExitCondition = vm.ExitTimeout | vm.ExitNormal | vm.ExitError
	}
	return ret, nil
}

func CreateExecProgInstance(vmPool *vm.Pool, vmIndex int, mgrCfg *mgrconfig.Config,
	reporter *report.Reporter, opt *OptionalConfig) (*ExecProgInstance, error) {
	vmInst, err := vmPool.Create(vmIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %v", err)
	}
	ret, err := SetupExecProg(vmInst, mgrCfg, reporter, opt)
	if err != nil {
		vmInst.Close()
		return nil, err
	}
	return ret, nil
}

func (inst *ExecProgInstance) runCommand(command string, duration time.Duration) (*RunResult, error) {
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
	outc, errc, err := inst.VMInstance.Run(duration, nil, command)
	if err != nil {
		return nil, fmt.Errorf("failed to run command in VM: %v", err)
	}
	result := &RunResult{
		ExecutionResult: *inst.VMInstance.MonitorExecutionRaw(outc, errc,
			inst.reporter, inst.ExitCondition, inst.BeforeContextLen),
	}
	if len(prefixOutput) > 0 {
		result.RawOutput = append(prefixOutput, result.RawOutput...)
	}
	if result.Report == nil {
		inst.Logf(2, "program did not crash")
	} else {
		if err := inst.reporter.Symbolize(result.Report); err != nil {
			return nil, fmt.Errorf("failed to symbolize report: %v", err)
		}
		inst.Logf(2, "program crashed: %v", result.Report.Title)
	}
	return result, nil
}

func (inst *ExecProgInstance) runBinary(bin string, duration time.Duration) (*RunResult, error) {
	bin, err := inst.VMInstance.Copy(bin)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy binary to VM: %v", err)}
	}
	return inst.runCommand(bin, duration)
}

func (inst *ExecProgInstance) RunCProg(p *prog.Prog, duration time.Duration,
	opts csource.Options) (*RunResult, error) {
	src, err := csource.Write(p, opts)
	if err != nil {
		return nil, err
	}
	inst.Logf(2, "testing compiled C program (duration=%v, %+v): %s", duration, opts, p)
	return inst.RunCProgRaw(src, p.Target, duration)
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
	opts csource.Options) (*RunResult, error) {
	vmProgFile, err := inst.VMInstance.Copy(progFile)
	if err != nil {
		return nil, &TestError{Title: fmt.Sprintf("failed to copy prog to VM: %v", err)}
	}
	target := inst.mgrCfg.SysTarget
	faultCall := -1
	if opts.Fault {
		faultCall = opts.FaultCall
	}
	command := ExecprogCmd(inst.execprogBin, inst.executorBin, target.OS, target.Arch, opts.Sandbox,
		opts.SandboxArg, opts.Repeat, opts.Threaded, opts.Collide, opts.Procs, faultCall, opts.FaultNth,
		!inst.OldFlagsCompatMode, inst.mgrCfg.Timeouts.Slowdown, vmProgFile)
	return inst.runCommand(command, duration)
}

func (inst *ExecProgInstance) RunSyzProg(syzProg []byte, duration time.Duration,
	opts csource.Options) (*RunResult, error) {
	progFile, err := osutil.WriteTempFile(syzProg)
	if err != nil {
		return nil, err
	}
	defer os.Remove(progFile)
	return inst.RunSyzProgFile(progFile, duration, opts)
}
