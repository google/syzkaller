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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/google/syzkaller/vm/vmimpl"

	// Import all VM implementations, so that users only need to import vm.
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/bhyve"
	_ "github.com/google/syzkaller/vm/cuttlefish"
	_ "github.com/google/syzkaller/vm/gce"
	_ "github.com/google/syzkaller/vm/gvisor"
	_ "github.com/google/syzkaller/vm/isolated"
	_ "github.com/google/syzkaller/vm/proxyapp"
	_ "github.com/google/syzkaller/vm/qemu"
	_ "github.com/google/syzkaller/vm/starnix"
	_ "github.com/google/syzkaller/vm/vmm"
	_ "github.com/google/syzkaller/vm/vmware"
)

type Pool struct {
	impl               vmimpl.Pool
	typ                vmimpl.Type
	workdir            string
	template           string
	timeouts           targets.Timeouts
	count              int
	activeCount        int32
	snapshot           bool
	hostFuzzer         bool
	statOutputReceived *stat.Val
}

type Instance struct {
	pool          *Pool
	impl          vmimpl.Instance
	workdir       string
	index         int
	snapshotSetup bool
	onClose       func()
}

var (
	Shutdown                = vmimpl.Shutdown
	ErrTimeout              = vmimpl.ErrTimeout
	_          BootErrorer  = vmimpl.BootError{}
	_          InfraErrorer = vmimpl.InfraError{}
)

func ShutdownCtx() context.Context {
	ctx, done := context.WithCancel(context.Background())
	go func() {
		<-Shutdown
		done()
	}()
	return ctx
}

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
		Snapshot:  cfg.Snapshot,
		Debug:     debug,
		Config:    cfg.VM,
		KernelSrc: cfg.KernelSrc,
	}
	impl, err := typ.Ctor(env)
	if err != nil {
		return nil, err
	}
	count := impl.Count()
	if debug && count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", count)
		count = 1
	}
	return &Pool{
		impl:       impl,
		typ:        typ,
		workdir:    env.Workdir,
		template:   cfg.WorkdirTemplate,
		timeouts:   cfg.Timeouts,
		count:      count,
		snapshot:   cfg.Snapshot,
		hostFuzzer: cfg.SysTarget.HostFuzzer,
		statOutputReceived: stat.New("vm output", "Bytes of VM console output received",
			stat.Graph("traffic"), stat.Rate{}, stat.FormatMB),
	}, nil
}

func (pool *Pool) Count() int {
	return pool.count
}

func (pool *Pool) Create(index int) (*Instance, error) {
	if index < 0 || index >= pool.count {
		return nil, fmt.Errorf("invalid VM index %v (count %v)", index, pool.count)
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
		pool:    pool,
		impl:    impl,
		workdir: workdir,
		index:   index,
		onClose: func() { atomic.AddInt32(&pool.activeCount, -1) },
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

// SetupSnapshot must be called once before calling RunSnapshot.
// Input is copied into the VM in an implementation defined way and is interpreted by executor.
func (inst *Instance) SetupSnapshot(input []byte) error {
	impl, ok := inst.impl.(snapshotter)
	if !ok {
		return errors.New("this VM type does not support snapshot mode")
	}
	if inst.snapshotSetup {
		return fmt.Errorf("SetupSnapshot called twice")
	}
	inst.snapshotSetup = true
	return impl.SetupSnapshot(input)
}

// RunSnapshot runs one input in snapshotting mode.
// Input is copied into the VM in an implementation defined way and is interpreted by executor.
// Result is the result provided by the executor.
// Output is the kernel console output during execution of the input.
func (inst *Instance) RunSnapshot(input []byte) (result, output []byte, err error) {
	impl, ok := inst.impl.(snapshotter)
	if !ok {
		return nil, nil, errors.New("this VM type does not support snapshot mode")
	}
	if !inst.snapshotSetup {
		return nil, nil, fmt.Errorf("RunSnapshot without SetupSnapshot")
	}
	// Executor has own timeout logic, so use a slightly larger timeout here.
	timeout := inst.pool.timeouts.Program / 5 * 7
	return impl.RunSnapshot(timeout, input)
}

type snapshotter interface {
	SetupSnapshot([]byte) error
	RunSnapshot(time.Duration, []byte) ([]byte, []byte, error)
}

func (inst *Instance) Copy(hostSrc string) (string, error) {
	return inst.impl.Copy(hostSrc)
}

func (inst *Instance) Forward(port int) (string, error) {
	return inst.impl.Forward(port)
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

type StopContext context.Context
type InjectExecuting <-chan bool
type OutputSize int

// An early notification that the command has finished / VM crashed.
type EarlyFinishCb func()

// Run runs cmd inside of the VM (think of ssh cmd) and monitors command execution
// and the kernel console output. It detects kernel oopses in output, lost connections, hangs, etc.
// Returns command+kernel output and a non-symbolized crash report (nil if no error happens).
// Accepted options:
//   - StopContext: the context to be used to prematurely stop the command
//   - ExitCondition: says which exit modes should be considered as errors/OK
//   - OutputSize: how much output to keep/return
func (inst *Instance) Run(timeout time.Duration, reporter *report.Reporter, command string, opts ...any) (
	[]byte, *report.Report, error) {
	exit := ExitNormal
	var stop <-chan bool
	var injected <-chan bool
	var finished func()
	outputSize := beforeContextDefault
	for _, o := range opts {
		switch opt := o.(type) {
		case ExitCondition:
			exit = opt
		case StopContext:
			stopCh := make(chan bool)
			go func() {
				<-opt.Done()
				close(stopCh)
			}()
			stop = stopCh
		case OutputSize:
			outputSize = int(opt)
		case InjectExecuting:
			injected = (<-chan bool)(opt)
		case EarlyFinishCb:
			finished = opt
		default:
			panic(fmt.Sprintf("unknown option %#v", opt))
		}
	}
	outc, errc, err := inst.impl.Run(timeout, stop, command)
	if err != nil {
		return nil, nil, err
	}
	mon := &monitor{
		inst:            inst,
		outc:            outc,
		injected:        injected,
		errc:            errc,
		finished:        finished,
		reporter:        reporter,
		beforeContext:   outputSize,
		exit:            exit,
		lastExecuteTime: time.Now(),
	}
	rep := mon.monitorExecution()
	return mon.output, rep, nil
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

func (inst *Instance) Index() int {
	return inst.index
}

func (inst *Instance) Close() error {
	err := inst.impl.Close()
	if retErr := os.RemoveAll(inst.workdir); err == nil {
		err = retErr
	}
	inst.onClose()
	return err
}

type Dispatcher = dispatcher.Pool[*Instance]

func NewDispatcher(pool *Pool, def dispatcher.Runner[*Instance]) *Dispatcher {
	return dispatcher.NewPool(pool.count, pool.Create, def)
}

type monitor struct {
	inst            *Instance
	outc            <-chan []byte
	injected        <-chan bool
	finished        func()
	errc            <-chan error
	reporter        *report.Reporter
	exit            ExitCondition
	output          []byte
	beforeContext   int
	matchPos        int
	lastExecuteTime time.Time
	extractCalled   bool
}

func (mon *monitor) monitorExecution() *report.Report {
	ticker := time.NewTicker(tickerPeriod * mon.inst.pool.timeouts.Scale)
	defer ticker.Stop()
	defer func() {
		if mon.finished != nil {
			mon.finished()
		}
	}()
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
			mon.inst.pool.statOutputReceived.Add(len(out))
			if rep, done := mon.appendOutput(out); done {
				return rep
			}
		case <-mon.injected:
			mon.lastExecuteTime = time.Now()
		case <-ticker.C:
			// Detect both "no output whatsoever" and "kernel episodically prints
			// something to console, but fuzzer is not actually executing programs".
			if time.Since(mon.lastExecuteTime) > mon.inst.pool.timeouts.NoOutput {
				return mon.extractError(noOutputCrash)
			}
		case <-Shutdown:
			return nil
		}
	}
}

func (mon *monitor) appendOutput(out []byte) (*report.Report, bool) {
	lastPos := len(mon.output)
	mon.output = append(mon.output, out...)
	if bytes.Contains(mon.output[lastPos:], executingProgram) {
		mon.lastExecuteTime = time.Now()
	}
	if mon.reporter.ContainsCrash(mon.output[mon.matchPos:]) {
		return mon.extractError("unknown error"), true
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
	mon.matchPos = max(mon.matchPos, 0)
	return nil, false
}

func (mon *monitor) extractError(defaultError string) *report.Report {
	if mon.extractCalled {
		panic("extractError called twice")
	}
	mon.extractCalled = true
	if mon.finished != nil {
		// If the caller wanted an early notification, provide it.
		mon.finished()
		mon.finished = nil
	}
	diagOutput, diagWait := []byte{}, false
	if defaultError != "" {
		diagOutput, diagWait = mon.inst.diagnose(mon.createReport(defaultError))
	}
	// Give it some time to finish writing the error message.
	// But don't wait for "no output", we already waited enough.
	if defaultError != noOutputCrash || diagWait {
		mon.waitForOutput()
	}
	// Check the executorPreemptedStr only for preemptible instances since executor can print
	// the string spuriously in some cases (gets SIGTERM from test program somehow).
	if mon.inst.pool.typ.Preemptible && bytes.Contains(mon.output, []byte(executorPreemptedStr)) {
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
		typ := crash.UnknownType
		if defaultError == lostConnectionCrash {
			typ = crash.LostConnection
		}
		return &report.Report{
			Title:      defaultError,
			Output:     mon.output,
			Suppressed: report.IsSuppressed(mon.reporter, mon.output),
			Type:       typ,
		}
	}
	start := max(rep.StartPos-mon.beforeContext, 0)
	end := min(rep.EndPos+afterContext, len(rep.Output))
	rep.Output = rep.Output[start:end]
	rep.StartPos -= start
	rep.EndPos -= start
	return rep
}

func (mon *monitor) waitForOutput() {
	timer := time.NewTimer(vmimpl.WaitForOutputTimeout * mon.inst.pool.timeouts.Scale)
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

	lostConnectionCrash  = "lost connection to test machine"
	noOutputCrash        = "no output from test machine"
	timeoutCrash         = "timed out"
	executorPreemptedStr = "SYZ-EXECUTOR: PREEMPTED"
	vmDiagnosisStart     = "\nVM DIAGNOSIS:\n"
)

var (
	executingProgram = []byte("executed programs:") // syz-execprog output

	beforeContextDefault = 128 << 10
	afterContext         = 128 << 10

	tickerPeriod = 10 * time.Second
)
