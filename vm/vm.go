// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vm provides an abstract test machine (VM, physical machine, etc)
// interface for the rest of the system.
// For convenience test machines are subsequently collectively called VMs.
// Package wraps vmimpl package interface with some common functionality
// and higher-level interface.
package vm

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"

	// Import all VM implementations, so that users only need to import vm.
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/bhyve"
	_ "github.com/google/syzkaller/vm/cuttlefish"
	_ "github.com/google/syzkaller/vm/gce"
	_ "github.com/google/syzkaller/vm/gvisor"
	_ "github.com/google/syzkaller/vm/isolated"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/odroid"
	_ "github.com/google/syzkaller/vm/proxyapp"
	_ "github.com/google/syzkaller/vm/qemu"
	_ "github.com/google/syzkaller/vm/starnix"
	_ "github.com/google/syzkaller/vm/vmm"
	_ "github.com/google/syzkaller/vm/vmware"
)

type Pool struct {
	impl        vmimpl.Pool
	workdir     string
	template    string
	timeouts    targets.Timeouts
	activeCount int32
}

type Instance struct {
	impl     vmimpl.Instance
	workdir  string
	timeouts targets.Timeouts
	index    int
	onClose  func()
}

var (
	Shutdown                = vmimpl.Shutdown
	ErrTimeout              = vmimpl.ErrTimeout
	_          BootErrorer  = vmimpl.BootError{}
	_          InfraErrorer = vmimpl.InfraError{}
)

type BootErrorer interface {
	BootError() (string, []byte)
}

type InfraErrorer interface {
	InfraError() (string, []byte)
}

// vmType splits the VM type from any suffix (separated by ":"). This is mostly
// useful for the "proxyapp" type, where pkg/build needs to specify/handle
// sub-types.
func vmType(fullName string) string {
	name, _, _ := strings.Cut(fullName, ":")
	return name
}

// AllowsOvercommit returns if the instance type allows overcommit of instances
// (i.e. creation of instances out-of-thin-air). Overcommit is used during image
// and patch testing in syz-ci when it just asks for more than specified in config
// instances. Generally virtual machines (qemu, gce) support overcommit,
// while physical machines (adb, isolated) do not. Strictly speaking, we should
// never use overcommit and use only what's specified in config, because we
// override resource limits specified in config (e.g. can OOM). But it works and
// makes lots of things much simpler.
func AllowsOvercommit(typ string) bool {
	return vmimpl.Types[vmType(typ)].Overcommit
}

// Create creates a VM pool that can be used to create individual VMs.
func Create(cfg *mgrconfig.Config, debug bool) (*Pool, error) {
	typ, ok := vmimpl.Types[vmType(cfg.Type)]
	if !ok {
		return nil, fmt.Errorf("unknown instance type '%v'", cfg.Type)
	}
	env := &vmimpl.Env{
		Name:      cfg.Name,
		OS:        cfg.TargetOS,
		Arch:      cfg.TargetVMArch,
		Workdir:   cfg.Workdir,
		Image:     cfg.Image,
		SSHKey:    cfg.SSHKey,
		SSHUser:   cfg.SSHUser,
		Timeouts:  cfg.Timeouts,
		Debug:     debug,
		Config:    cfg.VM,
		KernelSrc: cfg.KernelSrc,
	}
	impl, err := typ.Ctor(env)
	if err != nil {
		return nil, err
	}
	return &Pool{
		impl:     impl,
		workdir:  env.Workdir,
		template: cfg.WorkdirTemplate,
		timeouts: cfg.Timeouts,
	}, nil
}

func (pool *Pool) Count() int {
	return pool.impl.Count()
}

func (pool *Pool) Create(index int) (*Instance, error) {
	if index < 0 || index >= pool.Count() {
		return nil, fmt.Errorf("invalid VM index %v (count %v)", index, pool.Count())
	}
	workdir, err := osutil.ProcessTempDir(pool.workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance temp dir: %w", err)
	}
	if pool.template != "" {
		if err := osutil.CopyDirRecursively(pool.template, filepath.Join(workdir, "template")); err != nil {
			return nil, err
		}
	}
	impl, err := pool.impl.Create(workdir, index)
	if err != nil {
		os.RemoveAll(workdir)
		return nil, err
	}
	atomic.AddInt32(&pool.activeCount, 1)
	return &Instance{
		impl:     impl,
		workdir:  workdir,
		timeouts: pool.timeouts,
		index:    index,
		onClose:  func() { atomic.AddInt32(&pool.activeCount, -1) },
	}, nil
}

// TODO: Integration or end-to-end testing is needed.
//
//	https://github.com/google/syzkaller/pull/3269#discussion_r967650801
func (pool *Pool) Close() error {
	if pool.activeCount != 0 {
		panic("all the instances should be closed before pool.Close()")
	}
	if closer, ok := pool.impl.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (inst *Instance) Copy(hostSrc string) (string, error) {
	return inst.impl.Copy(hostSrc)
}

func (inst *Instance) Forward(port int) (string, error) {
	return inst.impl.Forward(port)
}

func (inst *Instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	outc <-chan []byte, errc <-chan error, err error) {
	return inst.impl.Run(timeout, stop, command)
}

func (inst *Instance) Info() ([]byte, error) {
	if ii, ok := inst.impl.(vmimpl.Infoer); ok {
		return ii.Info()
	}
	return nil, nil
}

func (inst *Instance) diagnose(rep *report.Report) ([]byte, bool) {
	if rep == nil {
		panic("rep is nil")
	}
	return inst.impl.Diagnose(rep)
}

func (inst *Instance) Close() {
	inst.impl.Close()
	os.RemoveAll(inst.workdir)
	inst.onClose()
}

type ExitCondition int

const (
	// The program is allowed to exit after timeout.
	ExitTimeout = ExitCondition(1 << iota)
	// The program is allowed to exit with no errors.
	ExitNormal
	// The program is allowed to exit with errors.
	ExitError
)

// MonitorExecution monitors execution of a program running inside of a VM.
// It detects kernel oopses in output, lost connections, hangs, etc.
// outc/errc is what vm.Instance.Run returns, reporter parses kernel output for oopses.
// Exit says which exit modes should be considered as errors/OK.
// Returns a non-symbolized crash report, or nil if no error happens.
func (inst *Instance) MonitorExecution(outc <-chan []byte, errc <-chan error,
	reporter *report.Reporter, exit ExitCondition) (rep *report.Report) {
	return inst.MonitorExecutionRaw(outc, errc, reporter, exit, 0).Report
}

type ExecutionResult struct {
	Report    *report.Report
	RawOutput []byte
}

func (inst *Instance) MonitorExecutionRaw(outc <-chan []byte, errc <-chan error,
	reporter *report.Reporter, exit ExitCondition, beforeContextSize int) (res *ExecutionResult) {
	if beforeContextSize == 0 {
		beforeContextSize = beforeContextDefault
	}
	mon := &monitor{
		inst:          inst,
		outc:          outc,
		errc:          errc,
		reporter:      reporter,
		beforeContext: beforeContextSize,
		exit:          exit,
	}
	return &ExecutionResult{
		Report:    mon.monitorExecution(),
		RawOutput: mon.output,
	}
}

type monitor struct {
	inst          *Instance
	outc          <-chan []byte
	errc          <-chan error
	reporter      *report.Reporter
	exit          ExitCondition
	output        []byte
	beforeContext int
	matchPos      int
}

func (mon *monitor) monitorExecution() *report.Report {
	ticker := time.NewTicker(tickerPeriod * mon.inst.timeouts.Scale)
	defer ticker.Stop()
	lastExecuteTime := time.Now()
	for {
		select {
		case err := <-mon.errc:
			switch err {
			case nil:
				// The program has exited without errors,
				// but wait for kernel output in case there is some delayed oops.
				crash := ""
				if mon.exit&ExitNormal == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractError(crash)
			case ErrTimeout:
				if mon.exit&ExitTimeout == 0 {
					return mon.extractError(timeoutCrash)
				}
				return nil
			default:
				// Note: connection lost can race with a kernel oops message.
				// In such case we want to return the kernel oops.
				crash := ""
				if mon.exit&ExitError == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractError(crash)
			}
		case out, ok := <-mon.outc:
			if !ok {
				mon.outc = nil
				continue
			}
			lastPos := len(mon.output)
			mon.output = append(mon.output, out...)
			if bytes.Contains(mon.output[lastPos:], executingProgram1) ||
				bytes.Contains(mon.output[lastPos:], executingProgram2) {
				lastExecuteTime = time.Now()
			}
			if mon.reporter.ContainsCrash(mon.output[mon.matchPos:]) {
				return mon.extractError("unknown error")
			}
			if len(mon.output) > 2*mon.beforeContext {
				copy(mon.output, mon.output[len(mon.output)-mon.beforeContext:])
				mon.output = mon.output[:mon.beforeContext]
			}
			// Find the starting position for crash matching on the next iteration.
			// We step back from the end of output by maxErrorLength to handle the case
			// when a crash line is currently split/incomplete. And then we try to find
			// the preceding '\n' to have a full line. This is required to handle
			// the case when a particular pattern is ignored as crash, but a suffix
			// of the pattern is detected as crash (e.g. "ODEBUG:" is trimmed to "BUG:").
			mon.matchPos = len(mon.output) - maxErrorLength
			for i := 0; i < maxErrorLength; i++ {
				if mon.matchPos <= 0 || mon.output[mon.matchPos-1] == '\n' {
					break
				}
				mon.matchPos--
			}
			if mon.matchPos < 0 {
				mon.matchPos = 0
			}
		case <-ticker.C:
			// Detect both "no output whatsoever" and "kernel episodically prints
			// something to console, but fuzzer is not actually executing programs".
			if time.Since(lastExecuteTime) > mon.inst.timeouts.NoOutput {
				return mon.extractError(noOutputCrash)
			}
		case <-Shutdown:
			return nil
		}
	}
}

func (mon *monitor) extractError(defaultError string) *report.Report {
	diagOutput, diagWait := []byte{}, false
	if defaultError != "" {
		diagOutput, diagWait = mon.inst.diagnose(mon.createReport(defaultError))
	}
	// Give it some time to finish writing the error message.
	// But don't wait for "no output", we already waited enough.
	if defaultError != noOutputCrash || diagWait {
		mon.waitForOutput()
	}
	if bytes.Contains(mon.output, []byte(fuzzerPreemptedStr)) {
		return nil
	}
	if defaultError == "" && mon.reporter.ContainsCrash(mon.output[mon.matchPos:]) {
		// We did not call Diagnose above because we thought there is no error, so call it now.
		diagOutput, diagWait = mon.inst.diagnose(mon.createReport(defaultError))
		if diagWait {
			mon.waitForOutput()
		}
	}
	rep := mon.createReport(defaultError)
	if rep == nil {
		return nil
	}
	if len(diagOutput) > 0 {
		rep.Output = append(rep.Output, vmDiagnosisStart...)
		rep.Output = append(rep.Output, diagOutput...)
	}
	return rep
}

func (mon *monitor) createReport(defaultError string) *report.Report {
	rep := mon.reporter.ParseFrom(mon.output, mon.matchPos)
	if rep == nil {
		if defaultError == "" {
			return nil
		}
		return &report.Report{
			Title:      defaultError,
			Output:     mon.output,
			Suppressed: report.IsSuppressed(mon.reporter, mon.output),
		}
	}
	start := rep.StartPos - mon.beforeContext
	if start < 0 {
		start = 0
	}
	end := rep.EndPos + afterContext
	if end > len(rep.Output) {
		end = len(rep.Output)
	}
	rep.Output = rep.Output[start:end]
	rep.StartPos -= start
	rep.EndPos -= start
	return rep
}

func (mon *monitor) waitForOutput() {
	timer := time.NewTimer(waitForOutputTimeout * mon.inst.timeouts.Scale)
	defer timer.Stop()
	for {
		select {
		case out, ok := <-mon.outc:
			if !ok {
				return
			}
			mon.output = append(mon.output, out...)
		case <-timer.C:
			return
		case <-Shutdown:
			return
		}
	}
}

const (
	maxErrorLength = 256

	lostConnectionCrash = "lost connection to test machine"
	noOutputCrash       = "no output from test machine"
	timeoutCrash        = "timed out"
	fuzzerPreemptedStr  = "SYZ-FUZZER: PREEMPTED"
	vmDiagnosisStart    = "\nVM DIAGNOSIS:\n"
)

var (
	executingProgram1 = []byte("executing program")  // syz-fuzzer, syz-runner output
	executingProgram2 = []byte("executed programs:") // syz-execprog output

	beforeContextDefault = 1024 << 10
	afterContext         = 128 << 10

	tickerPeriod         = 10 * time.Second
	waitForOutputTimeout = 10 * time.Second
)
