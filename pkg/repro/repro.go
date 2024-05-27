// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/bisect/minimize"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

type Result struct {
	Prog     *prog.Prog
	Duration time.Duration
	Opts     csource.Options
	CRepro   bool
	// Information about the final (non-symbolized) crash that we reproduced.
	// Can be different from what we started reproducing.
	Report *report.Report
}

type Stats struct {
	Log              []byte
	ExtractProgTime  time.Duration
	MinimizeProgTime time.Duration
	SimplifyProgTime time.Duration
	ExtractCTime     time.Duration
	SimplifyCTime    time.Duration
}

type reproInstance struct {
	index    int
	execProg execInterface
}

type context struct {
	logf         func(string, ...interface{})
	target       *targets.Target
	reporter     *report.Reporter
	crashTitle   string
	crashType    crash.Type
	crashStart   int
	entries      []*prog.LogEntry
	instances    chan *reproInstance
	bootRequests chan int
	testTimeouts []time.Duration
	startOpts    csource.Options
	stats        *Stats
	report       *report.Report
	timeouts     targets.Timeouts
}

// execInterface describes what's needed from a VM by a pkg/repro.
type execInterface interface {
	Close()
	RunCProg(p *prog.Prog, duration time.Duration, opts csource.Options) (*instance.RunResult, error)
	RunSyzProg(syzProg []byte, duration time.Duration, opts csource.Options, exitCondition vm.ExitCondition) (
		*instance.RunResult, error)
}

var ErrNoPrograms = errors.New("crash log does not contain any programs")

func Run(crashLog []byte, cfg *mgrconfig.Config, features flatrpc.Feature, reporter *report.Reporter,
	vmPool *vm.Pool, vmIndexes []int) (*Result, *Stats, error) {
	ctx, err := prepareCtx(crashLog, cfg, features, reporter, len(vmIndexes))
	if err != nil {
		return nil, nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx.createInstances(cfg, vmPool)
	}()
	// Prepare VMs in advance.
	for _, idx := range vmIndexes {
		ctx.bootRequests <- idx
	}
	// Wait until all VMs are really released.
	defer wg.Wait()
	return ctx.run()
}

func prepareCtx(crashLog []byte, cfg *mgrconfig.Config, features flatrpc.Feature, reporter *report.Reporter,
	VMs int) (*context, error) {
	if VMs == 0 {
		return nil, fmt.Errorf("no VMs provided")
	}
	entries := cfg.Target.ParseLog(crashLog)
	if len(entries) == 0 {
		return nil, ErrNoPrograms
	}
	crashStart := len(crashLog)
	crashTitle, crashType := "", crash.UnknownType
	if rep := reporter.Parse(crashLog); rep != nil {
		crashStart = rep.StartPos
		crashTitle = rep.Title
		crashType = rep.Type
	}
	testTimeouts := []time.Duration{
		3 * cfg.Timeouts.Program, // to catch simpler crashes (i.e. no races and no hangs)
		20 * cfg.Timeouts.Program,
		cfg.Timeouts.NoOutputRunningTime, // to catch "no output", races and hangs
	}
	switch {
	case crashTitle == "":
		crashTitle = "no output/lost connection"
		// Lost connection can be detected faster,
		// but theoretically if it's caused by a race it may need the largest timeout.
		// No output can only be reproduced with the max timeout.
		// As a compromise we use the smallest and the largest timeouts.
		testTimeouts = []time.Duration{testTimeouts[0], testTimeouts[2]}
	case crashType == crash.MemoryLeak:
		// Memory leaks can't be detected quickly because of expensive setup and scanning.
		testTimeouts = testTimeouts[1:]
	case crashType == crash.Hang:
		testTimeouts = testTimeouts[2:]
	}
	ctx := &context{
		target:       cfg.SysTarget,
		reporter:     reporter,
		crashTitle:   crashTitle,
		crashType:    crashType,
		crashStart:   crashStart,
		entries:      entries,
		instances:    make(chan *reproInstance, VMs),
		bootRequests: make(chan int, VMs),
		testTimeouts: testTimeouts,
		startOpts:    createStartOptions(cfg, features, crashType),
		stats:        new(Stats),
		timeouts:     cfg.Timeouts,
	}
	ctx.reproLogf(0, "%v programs, %v VMs, timeouts %v", len(entries), VMs, testTimeouts)
	return ctx, nil
}

func (ctx *context) run() (*Result, *Stats, error) {
	// Indicate that we no longer need VMs.
	defer close(ctx.bootRequests)

	res, err := ctx.repro()
	if err != nil {
		return nil, nil, err
	}
	if res != nil {
		ctx.reproLogf(3, "repro crashed as (corrupted=%v):\n%s",
			ctx.report.Corrupted, ctx.report.Report)
		// Try to rerun the repro if the report is corrupted.
		for attempts := 0; ctx.report.Corrupted && attempts < 3; attempts++ {
			ctx.reproLogf(3, "report is corrupted, running repro again")
			if res.CRepro {
				_, err = ctx.testCProg(res.Prog, res.Duration, res.Opts)
			} else {
				_, err = ctx.testProg(res.Prog, res.Duration, res.Opts)
			}
			if err != nil {
				return nil, nil, err
			}
		}
		ctx.reproLogf(3, "final repro crashed as (corrupted=%v):\n%s",
			ctx.report.Corrupted, ctx.report.Report)
		res.Report = ctx.report
	}
	return res, ctx.stats, nil
}

func createStartOptions(cfg *mgrconfig.Config, features flatrpc.Feature,
	crashType crash.Type) csource.Options {
	opts := csource.DefaultOpts(cfg)
	if crashType == crash.MemoryLeak {
		opts.Leak = true
	}
	if features&flatrpc.FeatureNetInjection == 0 {
		opts.NetInjection = false
	}
	if features&flatrpc.FeatureNetDevices == 0 {
		opts.NetDevices = false
	}
	if features&flatrpc.FeatureDevlinkPCI == 0 {
		opts.DevlinkPCI = false
	}
	if features&flatrpc.FeatureNicVF == 0 {
		opts.NicVF = false
	}
	if features&flatrpc.FeatureUSBEmulation == 0 {
		opts.USB = false
	}
	if features&flatrpc.FeatureVhciInjection == 0 {
		opts.VhciInjection = false
	}
	if features&flatrpc.FeatureWifiEmulation == 0 {
		opts.Wifi = false
	}
	if features&flatrpc.FeatureLRWPANEmulation == 0 {
		opts.IEEE802154 = false
	}
	if features&flatrpc.FeatureSwap == 0 {
		opts.Swap = false
	}
	return opts
}

func (ctx *context) repro() (*Result, error) {
	// Cut programs that were executed after crash.
	for i, ent := range ctx.entries {
		if ent.Start > ctx.crashStart {
			ctx.entries = ctx.entries[:i]
			break
		}
	}

	reproStart := time.Now()
	defer func() {
		ctx.reproLogf(3, "reproducing took %s", time.Since(reproStart))
	}()

	res, err := ctx.extractProg(ctx.entries)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	res, err = ctx.minimizeProg(res)
	if err != nil {
		return nil, err
	}

	// Try extracting C repro without simplifying options first.
	res, err = ctx.extractC(res)
	if err != nil {
		return nil, err
	}

	// Simplify options and try extracting C repro.
	if !res.CRepro {
		res, err = ctx.simplifyProg(res)
		if err != nil {
			return nil, err
		}
	}

	// Simplify C related options.
	if res.CRepro {
		res, err = ctx.simplifyC(res)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (ctx *context) extractProg(entries []*prog.LogEntry) (*Result, error) {
	ctx.reproLogf(2, "extracting reproducer from %v programs", len(entries))
	start := time.Now()
	defer func() {
		ctx.stats.ExtractProgTime = time.Since(start)
	}()

	// Extract last program on every proc.
	procs := make(map[int]int)
	for i, ent := range entries {
		procs[ent.Proc] = i
	}
	var indices []int
	for _, idx := range procs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	var lastEntries []*prog.LogEntry
	for i := len(indices) - 1; i >= 0; i-- {
		lastEntries = append(lastEntries, entries[indices[i]])
	}
	for _, timeout := range ctx.testTimeouts {
		// Execute each program separately to detect simple crashes caused by a single program.
		// Programs are executed in reverse order, usually the last program is the guilty one.
		res, err := ctx.extractProgSingle(lastEntries, timeout)
		if err != nil {
			return nil, err
		}
		if res != nil {
			ctx.reproLogf(3, "found reproducer with %d syscalls", len(res.Prog.Calls))
			return res, nil
		}

		// Don't try bisecting if there's only one entry.
		if len(entries) == 1 {
			continue
		}

		// Execute all programs and bisect the log to find multiple guilty programs.
		res, err = ctx.extractProgBisect(entries, timeout)
		if err != nil {
			return nil, err
		}
		if res != nil {
			ctx.reproLogf(3, "found reproducer with %d syscalls", len(res.Prog.Calls))
			return res, nil
		}
	}

	ctx.reproLogf(0, "failed to extract reproducer")
	return nil, nil
}

func (ctx *context) extractProgSingle(entries []*prog.LogEntry, duration time.Duration) (*Result, error) {
	ctx.reproLogf(3, "single: executing %d programs separately with timeout %s", len(entries), duration)

	opts := ctx.startOpts
	for _, ent := range entries {
		crashed, err := ctx.testProg(ent.P, duration, opts)
		if err != nil {
			return nil, err
		}
		if crashed {
			res := &Result{
				Prog:     ent.P,
				Duration: duration * 3 / 2,
				Opts:     opts,
			}
			ctx.reproLogf(3, "single: successfully extracted reproducer")
			return res, nil
		}
	}

	ctx.reproLogf(3, "single: failed to extract reproducer")
	return nil, nil
}

func (ctx *context) extractProgBisect(entries []*prog.LogEntry, baseDuration time.Duration) (*Result, error) {
	ctx.reproLogf(3, "bisect: bisecting %d programs with base timeout %s", len(entries), baseDuration)

	opts := ctx.startOpts
	duration := func(entries int) time.Duration {
		return baseDuration + time.Duration(entries/4)*time.Second
	}

	// First check if replaying the log may crash the kernel at all.
	ret, err := ctx.testProgs(entries, duration(len(entries)), opts)
	if !ret {
		ctx.reproLogf(3, "replaying the whole log did not cause a kernel crash")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Bisect the log to find multiple guilty programs.
	entries, err = ctx.bisectProgs(entries, func(progs []*prog.LogEntry) (bool, error) {
		return ctx.testProgs(progs, duration(len(progs)), opts)
	})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// TODO: Minimize each program before concatenation.
	// TODO: Return multiple programs if concatenation fails.

	ctx.reproLogf(3, "bisect: %d programs left: \n\n%s\n", len(entries), encodeEntries(entries))
	ctx.reproLogf(3, "bisect: trying to concatenate")

	// Concatenate all programs into one.
	dur := duration(len(entries)) * 3 / 2
	return ctx.concatenateProgs(entries, dur)
}

// The bisected progs may exceed the prog.MaxCalls limit.
// So let's first try to drop unneeded calls.
func (ctx *context) concatenateProgs(entries []*prog.LogEntry, dur time.Duration) (*Result, error) {
	ctx.reproLogf(3, "bisect: concatenate %d entries", len(entries))
	if len(entries) > 1 {
		// There's a risk of exceeding prog.MaxCalls, so let's first minimize
		// all entries separately.
		for i := 0; i < len(entries); i++ {
			ctx.reproLogf(1, "minimizing program #%d before concatenation", i)
			callsBefore := len(entries[i].P.Calls)
			entries[i].P, _ = prog.Minimize(entries[i].P, -1, prog.MinimizeParams{
				RemoveCallsOnly: true,
			},
				func(p1 *prog.Prog, _ int) bool {
					var newEntries []*prog.LogEntry
					if i > 0 {
						newEntries = append(newEntries, entries[:i]...)
					}
					newEntries = append(newEntries, &prog.LogEntry{
						P: p1,
					})
					if i+1 < len(entries) {
						newEntries = append(newEntries, entries[i+1:]...)
					}
					crashed, err := ctx.testProgs(newEntries, dur, ctx.startOpts)
					if err != nil {
						ctx.reproLogf(0, "concatenation step failed with %v", err)
						return false
					}
					return crashed
				})
			ctx.reproLogf(1, "minimized %d calls -> %d calls", callsBefore, len(entries[i].P.Calls))
		}
	}
	p := &prog.Prog{
		Target: entries[0].P.Target,
	}
	for _, entry := range entries {
		p.Calls = append(p.Calls, entry.P.Calls...)
	}
	if len(p.Calls) > prog.MaxCalls {
		ctx.reproLogf(2, "bisect: concatenated prog still exceeds %d calls", prog.MaxCalls)
		return nil, nil
	}
	crashed, err := ctx.testProg(p, dur, ctx.startOpts)
	if err != nil {
		ctx.reproLogf(3, "bisect: error during concatenation testing: %v", err)
		return nil, err
	}
	if !crashed {
		ctx.reproLogf(3, "bisect: concatenated prog does not crash")
		return nil, nil
	}
	res := &Result{
		Prog:     p,
		Duration: dur,
		Opts:     ctx.startOpts,
	}
	ctx.reproLogf(3, "bisect: concatenation succeeded")
	return res, nil
}

// Minimize calls and arguments.
func (ctx *context) minimizeProg(res *Result) (*Result, error) {
	ctx.reproLogf(2, "minimizing guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.MinimizeProgTime = time.Since(start)
	}()

	res.Prog, _ = prog.Minimize(res.Prog, -1, prog.MinimizeParams{Light: true},
		func(p1 *prog.Prog, callIndex int) bool {
			crashed, err := ctx.testProg(p1, res.Duration, res.Opts)
			if err != nil {
				ctx.reproLogf(0, "minimization failed with %v", err)
				return false
			}
			return crashed
		})

	return res, nil
}

// Simplify repro options (threaded, sandbox, etc).
func (ctx *context) simplifyProg(res *Result) (*Result, error) {
	ctx.reproLogf(2, "simplifying guilty program options")
	start := time.Now()
	defer func() {
		ctx.stats.SimplifyProgTime = time.Since(start)
	}()

	// Do further simplifications.
	for _, simplify := range progSimplifies {
		opts := res.Opts
		if !simplify(&opts) || !checkOpts(&opts, ctx.timeouts, res.Duration) {
			continue
		}
		crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
		if err != nil {
			return nil, err
		}
		if !crashed {
			continue
		}
		res.Opts = opts
		// Simplification successful, try extracting C repro.
		res, err = ctx.extractC(res)
		if err != nil {
			return nil, err
		}
		if res.CRepro {
			return res, nil
		}
	}

	return res, nil
}

// Try triggering crash with a C reproducer.
func (ctx *context) extractC(res *Result) (*Result, error) {
	ctx.reproLogf(2, "extracting C reproducer")
	start := time.Now()
	defer func() {
		ctx.stats.ExtractCTime = time.Since(start)
	}()

	crashed, err := ctx.testCProg(res.Prog, res.Duration, res.Opts)
	if err != nil {
		return nil, err
	}
	res.CRepro = crashed
	return res, nil
}

// Try to simplify the C reproducer.
func (ctx *context) simplifyC(res *Result) (*Result, error) {
	ctx.reproLogf(2, "simplifying C reproducer")
	start := time.Now()
	defer func() {
		ctx.stats.SimplifyCTime = time.Since(start)
	}()

	for _, simplify := range cSimplifies {
		opts := res.Opts
		if !simplify(&opts) || !checkOpts(&opts, ctx.timeouts, res.Duration) {
			continue
		}
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return nil, err
		}
		if !crashed {
			continue
		}
		res.Opts = opts
	}
	return res, nil
}

func checkOpts(opts *csource.Options, timeouts targets.Timeouts, timeout time.Duration) bool {
	if !opts.Repeat && timeout >= time.Minute {
		// If we have a non-repeating C reproducer with timeout > vm.NoOutputTimeout and it hangs
		// (the reproducer itself does not terminate on its own, note: it does not have builtin timeout),
		// then we will falsely detect "not output from test machine" kernel bug.
		// We could fix it by adding a builtin timeout to such reproducers (like we have in all other cases).
		// However, then it will exit within few seconds and we will finish the test without actually waiting
		// for full vm.NoOutputTimeout, which breaks the whole reason of using vm.NoOutputTimeout in the first
		// place. So we would need something more elaborate: let the program exist after few seconds, but
		// continue waiting for kernel hang errors for minutes, but at the same time somehow ignore "no output"
		// error because it will be false in this case.
		// Instead we simply prohibit !Repeat with long timeouts.
		// It makes sense on its own to some degree: if we are chasing an elusive bug, repeating the test
		// will increase chances of reproducing it and can make the reproducer less flaky.
		// Syz repros does not have this problem because they always have internal timeout, however
		// (1) it makes sense on its own, (2) we will either not use the whole timeout or waste the remaining
		// time as mentioned above, (3) if we remove repeat for syz repro, we won't be able to handle it
		// when/if we switch to C repro (we can simplify options, but we can't "complicate" them back).
		return false
	}
	return true
}

func (ctx *context) testProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	entry := prog.LogEntry{P: p}
	return ctx.testProgs([]*prog.LogEntry{&entry}, duration, opts)
}

func (ctx *context) testWithInstance(callback func(execInterface) (rep *instance.RunResult,
	err error)) (bool, error) {
	var result *instance.RunResult
	var err error

	const attempts = 3
	for i := 0; i < attempts; i++ {
		// It's hard to classify all kinds of errors into the one worth repeating
		// and not. So let's just retry runs for all errors.
		// If the problem is transient, it will likely go away.
		// If the problem is permanent, it will just be the same.
		result, err = ctx.runOnInstance(callback)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	rep := result.Report
	if rep == nil {
		return false, nil
	}
	if rep.Suppressed {
		ctx.reproLogf(2, "suppressed program crash: %v", rep.Title)
		return false, nil
	}
	if ctx.crashType == crash.MemoryLeak && rep.Type != crash.MemoryLeak {
		ctx.reproLogf(2, "not a leak crash: %v", rep.Title)
		return false, nil
	}
	ctx.report = rep
	return true, nil
}

var ErrNoVMs = errors.New("all VMs failed to boot")

// A helper method for testWithInstance.
func (ctx *context) runOnInstance(callback func(execInterface) (rep *instance.RunResult,
	err error)) (*instance.RunResult, error) {
	inst := <-ctx.instances
	if inst == nil {
		return nil, ErrNoVMs
	}
	defer ctx.returnInstance(inst)
	return callback(inst.execProg)
}

func encodeEntries(entries []*prog.LogEntry) []byte {
	buf := new(bytes.Buffer)
	for _, ent := range entries {
		if len(ent.P.Calls) > prog.MaxCalls {
			panic("prog.MaxCalls is exceeded")
		}
		fmt.Fprintf(buf, "executing program %v:\n%v", ent.Proc, string(ent.P.Serialize()))
	}
	return buf.Bytes()
}

func (ctx *context) testProgs(entries []*prog.LogEntry, duration time.Duration, opts csource.Options) (
	crashed bool, err error) {
	if len(entries) == 0 {
		return false, fmt.Errorf("no programs to execute")
	}
	pstr := encodeEntries(entries)
	program := entries[0].P.String()
	if len(entries) > 1 {
		program = "["
		for i, entry := range entries {
			program += fmt.Sprintf("%v", len(entry.P.Calls))
			if i != len(entries)-1 {
				program += ", "
			}
		}
		program += "]"
	}
	ctx.reproLogf(2, "testing program (duration=%v, %+v): %s", duration, opts, program)
	ctx.reproLogf(3, "detailed listing:\n%s", pstr)
	return ctx.testWithInstance(func(exec execInterface) (*instance.RunResult, error) {
		return exec.RunSyzProg(pstr, duration, opts, instance.SyzExitConditions)
	})
}

func (ctx *context) testCProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	return ctx.testWithInstance(func(exec execInterface) (*instance.RunResult, error) {
		return exec.RunCProg(p, duration, opts)
	})
}

func (ctx *context) returnInstance(inst *reproInstance) {
	inst.execProg.Close()
	ctx.bootRequests <- inst.index
}

func (ctx *context) reproLogf(level int, format string, args ...interface{}) {
	if ctx.logf != nil {
		ctx.logf(format, args...)
	}
	prefix := fmt.Sprintf("reproducing crash '%v': ", ctx.crashTitle)
	log.Logf(level, prefix+format, args...)
	ctx.stats.Log = append(ctx.stats.Log, []byte(fmt.Sprintf(format, args...)+"\n")...)
}

func (ctx *context) bisectProgs(progs []*prog.LogEntry, pred func([]*prog.LogEntry) (bool, error)) (
	[]*prog.LogEntry, error) {
	// Set up progs bisection.
	ctx.reproLogf(3, "bisect: bisecting %d programs", len(progs))
	minimizePred := func(progs []*prog.LogEntry) (bool, error) {
		// Don't waste time testing empty crash log.
		if len(progs) == 0 {
			return false, nil
		}
		return pred(progs)
	}
	ret, err := minimize.Slice(minimize.Config[*prog.LogEntry]{
		Pred: minimizePred,
		// For flaky crashes we usually end up with too many chunks.
		// Continuing bisection would just take a lot of time and likely produce no result.
		MaxChunks: 6,
		Logf: func(msg string, args ...interface{}) {
			ctx.reproLogf(3, "bisect: "+msg, args...)
		},
	}, progs)
	if err == minimize.ErrTooManyChunks {
		ctx.reproLogf(3, "bisect: too many guilty chunks, aborting")
		return nil, nil
	}
	return ret, err
}

func (ctx *context) createInstances(cfg *mgrconfig.Config, vmPool *vm.Pool) {
	var wg sync.WaitGroup
	for vmIndex := range ctx.bootRequests {
		wg.Add(1)
		vmIndex := vmIndex
		go func() {
			defer wg.Done()

			for try := 0; ; try++ {
				select {
				case <-vm.Shutdown:
					return
				default:
				}
				inst, err := instance.CreateExecProgInstance(vmPool, vmIndex, cfg,
					ctx.reporter, &instance.OptionalConfig{Logf: ctx.reproLogf})
				if err != nil {
					ctx.reproLogf(0, "failed to boot instance (try %v): %v", try+1, err)
					time.Sleep(10 * time.Second)
					continue
				}
				ctx.instances <- &reproInstance{execProg: inst, index: vmIndex}
				break
			}
		}()
	}
	wg.Wait()
	// Clean up.
	close(ctx.instances)
	for inst := range ctx.instances {
		inst.execProg.Close()
	}
}

type Simplify func(opts *csource.Options) bool

var progSimplifies = []Simplify{
	func(opts *csource.Options) bool {
		if opts.Collide || !opts.Threaded {
			return false
		}
		opts.Threaded = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Repeat {
			return false
		}
		opts.Repeat = false
		opts.Cgroups = false
		opts.NetReset = false
		opts.Procs = 1
		return true
	},
	func(opts *csource.Options) bool {
		if opts.Procs == 1 {
			return false
		}
		opts.Procs = 1
		return true
	},
	func(opts *csource.Options) bool {
		if opts.Sandbox == "none" {
			return false
		}
		opts.Sandbox = "none"
		return true
	},
}

var cSimplifies = append(progSimplifies, []Simplify{
	func(opts *csource.Options) bool {
		if opts.Sandbox == "" {
			return false
		}
		opts.Sandbox = ""
		opts.NetInjection = false
		opts.NetDevices = false
		opts.NetReset = false
		opts.Cgroups = false
		opts.BinfmtMisc = false
		opts.CloseFDs = false
		opts.DevlinkPCI = false
		opts.NicVF = false
		opts.USB = false
		opts.VhciInjection = false
		opts.Wifi = false
		opts.Swap = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.NetInjection {
			return false
		}
		opts.NetInjection = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.NetDevices {
			return false
		}
		opts.NetDevices = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.NetReset {
			return false
		}
		opts.NetReset = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Cgroups {
			return false
		}
		opts.Cgroups = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.BinfmtMisc {
			return false
		}
		opts.BinfmtMisc = false
		return true
	},
	func(opts *csource.Options) bool {
		// We don't want to remove close_fds() call when repeat is enabled,
		// since that can lead to deadlocks, see executor/common_linux.h.
		if !opts.CloseFDs || opts.Repeat {
			return false
		}
		opts.CloseFDs = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.DevlinkPCI {
			return false
		}
		opts.DevlinkPCI = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.NicVF {
			return false
		}
		opts.NicVF = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.USB {
			return false
		}
		opts.USB = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.VhciInjection {
			return false
		}
		opts.VhciInjection = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Wifi {
			return false
		}
		opts.Wifi = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.IEEE802154 {
			return false
		}
		opts.IEEE802154 = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.UseTmpDir || opts.Sandbox == "namespace" || opts.Cgroups {
			return false
		}
		opts.UseTmpDir = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.HandleSegv {
			return false
		}
		opts.HandleSegv = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Sysctl {
			return false
		}
		opts.Sysctl = false
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Swap {
			return false
		}
		opts.Swap = false
		return true
	},
}...)
