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
	_ "github.com/google/syzkaller/vm/virtualbox"
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

func (pool *Pool) Create(ctx context.Context, index int) (*Instance, error) {
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
	impl, err := pool.impl.Create(ctx, workdir, index)
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

type RunOptions struct {
	// exitCondition says which exit modes should be considered as errors/OK
	exitCondition ExitCondition
	// BeforeContext is how many bytes BEFORE the crash description to keep in the report.
	beforeContext int
	// afterContext is how many bytes AFTER the crash description to keep in the report.
	afterContext int
	// An early notification that the command has finished / VM crashed.
	earlyFinishCb   func()
	injectExecuting <-chan bool
	tickerPeriod    time.Duration
}

func WithExitCondition(exitCondition ExitCondition) func(*RunOptions) {
	return func(opts *RunOptions) {
		opts.exitCondition = exitCondition
	}
}

func WithBeforeContext(beforeContext int) func(*RunOptions) {
	return func(opts *RunOptions) {
		opts.beforeContext = beforeContext
	}
}

func WithInjectExecuting(injectExecuting <-chan bool) func(*RunOptions) {
	return func(opts *RunOptions) {
		opts.injectExecuting = injectExecuting
	}
}

func WithEarlyFinishCb(cb func()) func(*RunOptions) {
	return func(opts *RunOptions) {
		opts.earlyFinishCb = cb
	}
}

// Run runs cmd inside of the VM (think of ssh cmd) and monitors command execution
// and the kernel console output. It detects kernel oopses in output, lost connections, hangs, etc.
// Returns command+kernel output and a non-symbolized crash report (nil if no error happens).
func (inst *Instance) Run(ctx context.Context, reporter *report.Reporter, command string, opts ...func(*RunOptions)) (
	[]byte, []*report.Report, error) {
	runOptions := &RunOptions{
		beforeContext: 128 << 10,
		afterContext:  128 << 10,
		tickerPeriod:  10 * time.Second,
	}
	for _, opt := range opts {
		opt(runOptions)
	}

	outc, errc, err := inst.impl.Run(ctx, command)
	if err != nil {
		return nil, nil, err
	}
	mon := &monitor{
		RunOptions:      runOptions,
		inst:            inst,
		outc:            outc,
		errc:            errc,
		reporter:        reporter,
		lastExecuteTime: time.Now(),
	}
	reps := mon.monitorExecution()
	return mon.output, reps, nil
}

func (inst *Instance) RunStream(ctx context.Context,
	command string) (<-chan vmimpl.Chunk, <-chan error, error) {
	return inst.impl.Run(ctx, command)
}

func (inst *Instance) Info() ([]byte, error) {
	if ii, ok := inst.impl.(vmimpl.Infoer); ok {
		return ii.Info()
	}
	return nil, nil
}

func (inst *Instance) diagnose(reps []*report.Report) ([]byte, bool) {
	if len(reps) == 0 {
		panic("reps is empty")
	}
	return inst.impl.Diagnose(reps[0])
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
	*RunOptions
	inst     *Instance
	outc     <-chan vmimpl.Chunk
	errc     <-chan error
	reporter *report.Reporter
	// output is at most mon.beforeContext + len(report) + afterContext bytes.
	output []byte
	// curPos in the output to scan for the matches.
	curPos          int
	lastExecuteTime time.Time
	// extractCalled is used to prevent multiple extractError calls.
	extractCalled bool
}

func (mon *monitor) monitorExecution() []*report.Report {
	ticker := time.NewTicker(mon.tickerPeriod * mon.inst.pool.timeouts.Scale)
	defer ticker.Stop()
	defer func() {
		if mon.earlyFinishCb != nil {
			mon.earlyFinishCb()
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
				if mon.exitCondition&ExitNormal == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractErrors(crash)
			case ErrTimeout:
				if mon.exitCondition&ExitTimeout == 0 {
					return mon.extractErrors(timeoutCrash)
				}
				return nil
			default:
				// Note: connection lost can race with a kernel oops message.
				// In such case we want to return the kernel oops.
				crash := ""
				if mon.exitCondition&ExitError == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractErrors(crash)
			}
		case chunk, ok := <-mon.outc:
			if !ok {
				mon.outc = nil
				continue
			}
			mon.inst.pool.statOutputReceived.Add(len(chunk.Data))
			if rep, done := mon.appendOutput(chunk.Data); done {
				return rep
			}
		case <-mon.injectExecuting:
			mon.lastExecuteTime = time.Now()
		case <-ticker.C:
			// Detect both "no output whatsoever" and "kernel episodically prints
			// something to console, but fuzzer is not actually executing programs".
			if time.Since(mon.lastExecuteTime) > mon.inst.pool.timeouts.NoOutput {
				return mon.extractErrors(noOutputCrash)
			}
		case <-Shutdown:
			return nil
		}
	}
}

func (mon *monitor) appendOutput(out []byte) ([]*report.Report, bool) {
	lastPos := len(mon.output)
	mon.output = append(mon.output, out...)
	if bytes.Contains(mon.output[lastPos:], []byte(executedProgramsStart)) {
		mon.lastExecuteTime = time.Now()
	}
	if mon.reporter.ContainsCrash(mon.output[mon.curPos:]) {
		return mon.extractErrors("unknown error"), true
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
	mon.curPos = len(mon.output) - maxErrorLength
	for i := 0; i < maxErrorLength; i++ {
		if mon.curPos <= 0 || mon.output[mon.curPos-1] == '\n' {
			break
		}
		mon.curPos--
	}
	mon.curPos = max(mon.curPos, 0)
	return nil, false
}

func (mon *monitor) extractErrors(defaultError string) []*report.Report {
	if mon.extractCalled {
		panic("extractError called twice")
	}
	mon.extractCalled = true
	if mon.earlyFinishCb != nil {
		mon.earlyFinishCb()
		mon.earlyFinishCb = nil
	}
	diagOutput, diagWait := []byte{}, false
	if defaultError != "" {
		diagOutput, diagWait = mon.inst.diagnose(mon.createReports(defaultError))
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
	if defaultError == "" && mon.reporter.ContainsCrash(mon.output[mon.curPos:]) {
		// We did not call Diagnose above because we thought there is no error, so call it now.
		diagOutput, diagWait = mon.inst.diagnose(mon.createReports(defaultError))
		if diagWait {
			mon.waitForOutput()
		}
	}
	reps := mon.createReports(defaultError)
	if len(reps) == 0 {
		return nil
	}
	if len(diagOutput) > 0 {
		reps[0].Output = append(reps[0].Output, vmDiagnosisStart...)
		reps[0].Output = append(reps[0].Output, diagOutput...)
	}
	return reps
}

func (mon *monitor) createReports(defaultError string) []*report.Report {
	curPos := mon.curPos
	var res []*report.Report
	for {
		rep := mon.reporter.ParseFrom(mon.output, curPos)
		if rep == nil {
			if defaultError == "" || len(res) > 0 {
				return res
			}
			typ := crash.UnknownType
			if defaultError == lostConnectionCrash {
				typ = crash.LostConnection
			}
			return []*report.Report{{
				Title:      defaultError,
				Output:     mon.output,
				Suppressed: report.IsSuppressed(mon.reporter, mon.output),
				Type:       typ,
			}}
		}
		curPos = rep.SkipPos
		start := max(rep.StartPos-mon.beforeContext, 0)
		end := min(rep.EndPos+mon.afterContext, len(rep.Output))
		rep.Output = rep.Output[start:end]
		rep.StartPos -= start
		rep.EndPos -= start
		if len(res) == 0 || (len(res) > 0 && !rep.Corrupted && !rep.Suppressed) {
			res = append(res, rep)
		}
	}
}

func (mon *monitor) waitForOutput() {
	timer := time.NewTimer(vmimpl.WaitForOutputTimeout * mon.inst.pool.timeouts.Scale)
	defer timer.Stop()
	for {
		select {
		case chunk, ok := <-mon.outc:
			if !ok {
				return
			}
			mon.output = append(mon.output, chunk.Data...)
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

	executorPreemptedStr  = "SYZ-EXECUTOR: PREEMPTED"
	vmDiagnosisStart      = "\nVM DIAGNOSIS:\n"
	executedProgramsStart = "executed programs:" // syz-execprog output
)
