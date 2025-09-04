// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
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
	"github.com/google/syzkaller/vm/dispatcher"
)

type Result struct {
	Prog     *prog.Prog
	Duration time.Duration
	Opts     csource.Options
	CRepro   bool
	// Information about the final (non-symbolized) crash that we reproduced.
	// Can be different from what we started reproducing.
	Report *report.Report
	// A very rough estimate of the probability with which the resulting syz
	// reproducer crashes the kernel.
	Reliability float64
}

type Stats struct {
	Log              []byte
	TotalTime        time.Duration
	ExtractProgTime  time.Duration
	MinimizeProgTime time.Duration
	SimplifyProgTime time.Duration
	ExtractCTime     time.Duration
	SimplifyCTime    time.Duration
}

type reproContext struct {
	ctx            context.Context
	exec           execInterface
	logf           func(string, ...interface{})
	target         *targets.Target
	crashTitle     string
	crashType      crash.Type
	crashStart     int
	crashExecutor  *report.ExecutorInfo
	entries        []*prog.LogEntry
	testTimeouts   []time.Duration
	startOpts      csource.Options
	stats          *Stats
	report         *report.Report
	timeouts       targets.Timeouts
	observedTitles map[string]bool
	fast           bool
}

// execInterface describes the interfaces needed by pkg/repro.
type execInterface interface {
	// Run() will either run a C repro or a syz repro depending on params.
	Run(ctx context.Context, params instance.ExecParams, logf instance.ExecutorLogger) (*instance.RunResult, error)
}

type Environment struct {
	Config   *mgrconfig.Config
	Features flatrpc.Feature
	Reporter *report.Reporter
	Pool     *vm.Dispatcher
	// The Fast repro mode restricts the repro log bisection,
	// it skips multiple simpifications and C repro generation.
	Fast bool

	logf func(string, ...interface{})
}

func Run(ctx context.Context, log []byte, env Environment) (*Result, *Stats, error) {
	return runInner(ctx, log, env, &poolWrapper{
		cfg:      env.Config,
		reporter: env.Reporter,
		pool:     env.Pool,
	})
}

var ErrEmptyCrashLog = errors.New("no programs")

func runInner(ctx context.Context, crashLog []byte, env Environment, exec execInterface) (*Result, *Stats, error) {
	cfg := env.Config
	entries := cfg.Target.ParseLog(crashLog, prog.NonStrict)
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("log (%d bytes) parse failed: %w", len(crashLog), ErrEmptyCrashLog)
	}
	crashStart := len(crashLog)
	crashTitle, crashType := "", crash.UnknownType
	var crashExecutor *report.ExecutorInfo
	if rep := env.Reporter.Parse(crashLog); rep != nil {
		crashStart = rep.StartPos
		crashTitle = rep.Title
		crashType = rep.Type
		crashExecutor = rep.Executor
	}
	testTimeouts := []time.Duration{
		max(30*time.Second, 3*cfg.Timeouts.Program), // to catch simpler crashes (i.e. no races and no hangs)
		max(100*time.Second, 20*cfg.Timeouts.Program),
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
	if env.Fast {
		testTimeouts = []time.Duration{30 * time.Second, 5 * time.Minute}
	}
	reproCtx := &reproContext{
		ctx:           ctx,
		exec:          exec,
		target:        cfg.SysTarget,
		crashTitle:    crashTitle,
		crashType:     crashType,
		crashStart:    crashStart,
		crashExecutor: crashExecutor,

		entries:        entries,
		testTimeouts:   testTimeouts,
		startOpts:      createStartOptions(cfg, env.Features, crashType),
		stats:          new(Stats),
		timeouts:       cfg.Timeouts,
		observedTitles: map[string]bool{},
		fast:           env.Fast,
		logf:           env.logf,
	}
	return reproCtx.run()
}

func (ctx *reproContext) run() (*Result, *Stats, error) {
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
				_, err = ctx.testCProg(res.Prog, res.Duration, res.Opts, false)
			} else {
				_, err = ctx.testProg(res.Prog, res.Duration, res.Opts, false)
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

func (ctx *reproContext) repro() (*Result, error) {
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
		ctx.stats.TotalTime = time.Since(reproStart)
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
	if !ctx.fast {
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
	}
	// Validate the resulting reproducer - a random rare kernel crash might have diverted the process.
	res.Reliability, err = calculateReliability(func() (bool, error) {
		ret, err := ctx.testProg(res.Prog, res.Duration, res.Opts, false)
		if err != nil {
			return false, err
		}
		ctx.reproLogf(2, "validation run: crashed=%v", ret.Crashed)
		return ret.Crashed, nil
	})
	if err != nil {
		ctx.reproLogf(2, "could not calculate reliability, err=%v", err)
		return nil, err
	}

	const minReliability = 0.15
	if res.Reliability < minReliability {
		ctx.reproLogf(1, "reproducer is too unreliable: %.2f", res.Reliability)
		return nil, err
	}

	return res, nil
}

func calculateReliability(cb func() (bool, error)) (float64, error) {
	const (
		maxRuns  = 10
		enoughOK = 3
	)
	total := 0
	okCount := 0
	for i := 0; i < maxRuns && okCount < enoughOK; i++ {
		total++
		ok, err := cb()
		if err != nil {
			return 0, err
		}
		if ok {
			okCount++
		}
	}
	return float64(okCount) / float64(total), nil
}

func (ctx *reproContext) extractProg(entries []*prog.LogEntry) (*Result, error) {
	ctx.reproLogf(2, "extracting reproducer from %v programs", len(entries))
	start := time.Now()
	defer func() {
		ctx.stats.ExtractProgTime = time.Since(start)
	}()

	var toTest []*prog.LogEntry
	if ctx.crashExecutor != nil {
		for _, entry := range entries {
			// Note: we don't check ProcID b/c hanged programs are assigned fake unique proc IDs
			// that don't match "Comm" in the kernel panic message.
			if entry.ID == ctx.crashExecutor.ExecID {
				toTest = append(toTest, entry)
				ctx.reproLogf(3, "first checking the prog from the crash report")
				break
			}
		}
	}

	if len(toTest) == 0 {
		ctx.reproLogf(3, "testing a last program of every proc")
		toTest = lastEntries(entries)
	}

	for i, timeout := range ctx.testTimeouts {
		// Execute each program separately to detect simple crashes caused by a single program.
		// Programs are executed in reverse order, usually the last program is the guilty one.
		res, err := ctx.extractProgSingle(toTest, timeout)
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

		if ctx.fast && i+1 < len(ctx.testTimeouts) {
			// Bisect only under the biggest timeout.
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

	ctx.reproLogf(2, "failed to extract reproducer")
	return nil, nil
}

// Extract last program on every proc.
func lastEntries(entries []*prog.LogEntry) []*prog.LogEntry {
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
	return lastEntries
}

func (ctx *reproContext) extractProgSingle(entries []*prog.LogEntry, duration time.Duration) (*Result, error) {
	ctx.reproLogf(3, "single: executing %d programs separately with timeout %s", len(entries), duration)

	opts := ctx.startOpts
	for _, ent := range entries {
		ret, err := ctx.testProg(ent.P, duration, opts, false)
		if err != nil {
			return nil, err
		}
		if ret.Crashed {
			res := &Result{
				Prog:     ent.P,
				Duration: max(duration, ret.Duration*3/2),
				Opts:     opts,
			}
			ctx.reproLogf(3, "single: successfully extracted reproducer")
			return res, nil
		}
	}

	ctx.reproLogf(3, "single: failed to extract reproducer")
	return nil, nil
}

func (ctx *reproContext) extractProgBisect(entries []*prog.LogEntry, baseDuration time.Duration) (*Result, error) {
	ctx.reproLogf(3, "bisect: bisecting %d programs with base timeout %s", len(entries), baseDuration)

	opts := ctx.startOpts
	duration := func(entries int) time.Duration {
		return baseDuration + time.Duration(entries/4)*time.Second
	}

	// First check if replaying the log may crash the kernel at all.
	ret, err := ctx.testProgs(entries, duration(len(entries)), opts, false)
	if !ret.Crashed {
		ctx.reproLogf(3, "replaying the whole log did not cause a kernel crash")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Bisect the log to find multiple guilty programs.
	entries, err = ctx.bisectProgs(entries, func(progs []*prog.LogEntry) (bool, error) {
		ret, err := ctx.testProgs(progs, duration(len(progs)), opts, false)
		return ret.Crashed, err
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
func (ctx *reproContext) concatenateProgs(entries []*prog.LogEntry, dur time.Duration) (*Result, error) {
	ctx.reproLogf(3, "bisect: concatenate %d entries", len(entries))
	if len(entries) > 1 {
		// There's a risk of exceeding prog.MaxCalls, so let's first minimize
		// all entries separately.
		for i := 0; i < len(entries); i++ {
			var testErr error
			ctx.reproLogf(2, "minimizing program #%d before concatenation", i)
			callsBefore := len(entries[i].P.Calls)
			entries[i].P, _ = prog.Minimize(entries[i].P, -1, prog.MinimizeCallsOnly,
				func(p1 *prog.Prog, _ int) bool {
					if testErr != nil {
						return false
					}
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
					ret, err := ctx.testProgs(newEntries, dur, ctx.startOpts, false)
					if err != nil {
						testErr = err
						ctx.reproLogf(0, "concatenation step failed with %v", err)
						return false
					}
					return ret.Crashed
				})
			if testErr != nil {
				return nil, testErr
			}
			ctx.reproLogf(2, "minimized %d calls -> %d calls", callsBefore, len(entries[i].P.Calls))
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
	ret, err := ctx.testProg(p, dur, ctx.startOpts, false)
	if err != nil {
		ctx.reproLogf(3, "bisect: error during concatenation testing: %v", err)
		return nil, err
	}
	if !ret.Crashed {
		ctx.reproLogf(3, "bisect: concatenated prog does not crash")
		return nil, nil
	}
	res := &Result{
		Prog:     p,
		Duration: min(dur, ret.Duration*2),
		Opts:     ctx.startOpts,
	}
	ctx.reproLogf(3, "bisect: concatenation succeeded")
	return res, nil
}

// Minimize calls and arguments.
func (ctx *reproContext) minimizeProg(res *Result) (*Result, error) {
	ctx.reproLogf(2, "minimizing guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.MinimizeProgTime = time.Since(start)
	}()

	mode := prog.MinimizeCrash
	if ctx.fast {
		mode = prog.MinimizeCallsOnly
	}
	var testErr error
	res.Prog, _ = prog.Minimize(res.Prog, -1, mode, func(p1 *prog.Prog, callIndex int) bool {
		if testErr != nil {
			return false
		}
		if len(p1.Calls) == 0 {
			// We do want to keep at least one call, otherwise tools/syz-execprog
			// will immediately exit.
			return false
		}
		ret, err := ctx.testProg(p1, res.Duration, res.Opts, false)
		if err != nil {
			ctx.reproLogf(2, "minimization failed with %v", err)
			testErr = err
			return false
		}
		return ret.Crashed
	})
	if testErr != nil {
		return res, nil
	}
	return res, nil
}

// Simplify repro options (threaded, sandbox, etc).
func (ctx *reproContext) simplifyProg(res *Result) (*Result, error) {
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
		ret, err := ctx.testProg(res.Prog, res.Duration, opts, true)
		if err != nil {
			return nil, err
		}
		if !ret.Crashed {
			continue
		}
		res.Opts = opts
		if ctx.fast {
			continue
		}
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
func (ctx *reproContext) extractC(res *Result) (*Result, error) {
	ctx.reproLogf(2, "extracting C reproducer")
	start := time.Now()
	defer func() {
		ctx.stats.ExtractCTime = time.Since(start)
	}()

	ret, err := ctx.testCProg(res.Prog, res.Duration, res.Opts, true)
	if err != nil {
		return nil, err
	}
	res.CRepro = ret.Crashed
	return res, nil
}

// Try to simplify the C reproducer.
func (ctx *reproContext) simplifyC(res *Result) (*Result, error) {
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
		ret, err := ctx.testCProg(res.Prog, res.Duration, opts, true)
		if err != nil {
			return nil, err
		}
		if !ret.Crashed {
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

func (ctx *reproContext) testProg(p *prog.Prog, duration time.Duration, opts csource.Options,
	strict bool) (ret verdict, err error) {
	entry := prog.LogEntry{P: p}
	return ctx.testProgs([]*prog.LogEntry{&entry}, duration, opts, strict)
}

type verdict struct {
	Crashed  bool
	Duration time.Duration
}

func (ctx *reproContext) getVerdict(callback func() (rep *instance.RunResult, err error), strict bool) (
	verdict, error) {
	var result *instance.RunResult
	var err error

	const attempts = 3
	for i := 0; i < attempts; i++ {
		// It's hard to classify all kinds of errors into the one worth repeating
		// and not. So let's just retry runs for all errors.
		// If the problem is transient, it will likely go away.
		// If the problem is permanent, it will just be the same.
		result, err = callback()
		if err == nil {
			break
		}
	}
	if err != nil {
		return verdict{}, err
	}
	rep := result.Report
	if rep == nil {
		return verdict{false, result.Duration}, nil
	}
	if rep.Suppressed {
		ctx.reproLogf(2, "suppressed program crash: %v", rep.Title)
		return verdict{false, result.Duration}, nil
	}
	if ctx.crashType == crash.MemoryLeak && rep.Type != crash.MemoryLeak {
		ctx.reproLogf(2, "not a leak crash: %v", rep.Title)
		return verdict{false, result.Duration}, nil
	}
	if strict && len(ctx.observedTitles) > 0 {
		if !ctx.observedTitles[rep.Title] {
			ctx.reproLogf(2, "a never seen crash title: %v, ignore", rep.Title)
			return verdict{false, result.Duration}, nil
		}
	} else {
		ctx.observedTitles[rep.Title] = true
	}
	ctx.report = rep
	return verdict{true, result.Duration}, nil
}

var ErrNoVMs = errors.New("all VMs failed to boot")

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

func (ctx *reproContext) testProgs(entries []*prog.LogEntry, duration time.Duration, opts csource.Options,
	strict bool) (ret verdict, err error) {
	if len(entries) == 0 {
		return ret, fmt.Errorf("no programs to execute")
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
	return ctx.getVerdict(func() (*instance.RunResult, error) {
		return ctx.exec.Run(ctx.ctx, instance.ExecParams{
			SyzProg:  pstr,
			Opts:     opts,
			Duration: duration,
		}, ctx.reproLogf)
	}, strict)
}

func (ctx *reproContext) testCProg(p *prog.Prog, duration time.Duration, opts csource.Options,
	strict bool) (ret verdict, err error) {
	return ctx.getVerdict(func() (*instance.RunResult, error) {
		return ctx.exec.Run(ctx.ctx, instance.ExecParams{
			CProg:    p,
			Opts:     opts,
			Duration: duration,
		}, ctx.reproLogf)
	}, strict)
}

func (ctx *reproContext) reproLogf(level int, format string, args ...interface{}) {
	if ctx.logf != nil {
		ctx.logf(format, args...)
	}
	prefix := fmt.Sprintf("reproducing crash '%v': ", ctx.crashTitle)
	log.Logf(level, prefix+format, args...)
	ctx.stats.Log = append(ctx.stats.Log, []byte(fmt.Sprintf(format, args...)+"\n")...)
}

func (ctx *reproContext) bisectProgs(progs []*prog.LogEntry, pred func([]*prog.LogEntry) (bool, error)) (
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
	// For flaky crashes we usually end up with too many chunks.
	// Continuing bisection would just take a lot of time and likely produce no result.
	chunks := 6
	if ctx.fast {
		chunks = 2
	}
	ret, err := minimize.SliceWithFixed(minimize.Config[*prog.LogEntry]{
		Pred:      minimizePred,
		MaxChunks: chunks,
		Logf: func(msg string, args ...interface{}) {
			ctx.reproLogf(3, "bisect: "+msg, args...)
		},
	}, progs, func(elem *prog.LogEntry) bool {
		if ctx.crashExecutor == nil {
			return false
		}
		// If the program was mentioned in the crash report, always keep it during bisection.
		return elem.ID == ctx.crashExecutor.ExecID
	})
	if err == minimize.ErrTooManyChunks {
		ctx.reproLogf(3, "bisect: too many guilty chunks, aborting")
		return nil, nil
	}
	return ret, err
}

type poolWrapper struct {
	cfg      *mgrconfig.Config
	reporter *report.Reporter
	pool     *vm.Dispatcher
}

func (pw *poolWrapper) Run(ctx context.Context, params instance.ExecParams,
	logf instance.ExecutorLogger) (*instance.RunResult, error) {
	if err := ctx.Err(); err != nil {
		// Note that we could also propagate ctx down to SetupExecProg() and RunCProg() operations,
		// but so far it does not seem to be worth the effort.
		return nil, err
	}

	var result *instance.RunResult
	var err error
	runErr := pw.pool.Run(ctx, func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
		updInfo(func(info *dispatcher.Info) {
			typ := "syz"
			if params.CProg != nil {
				typ = "C"
			}
			info.Status = fmt.Sprintf("reproducing (%s, %.1f min)", typ, params.Duration.Minutes())
		})
		var ret *instance.ExecProgInstance
		ret, err = instance.SetupExecProg(inst, pw.cfg, pw.reporter,
			&instance.OptionalConfig{Logf: logf})
		if err != nil {
			return
		}
		if params.CProg != nil {
			result, err = ret.RunCProg(params)
		} else {
			result, err = ret.RunSyzProg(params)
		}
	})
	if runErr != nil {
		return nil, runErr
	}
	return result, err
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
		if opts.ProcRestartFreq == 0 {
			return false
		}
		opts.ProcRestartFreq = 0
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

func (stats *Stats) FullLog() []byte {
	if stats == nil {
		return nil
	}
	return []byte(fmt.Sprintf("Extracting prog: %v\nMinimizing prog: %v\n"+
		"Simplifying prog options: %v\nExtracting C: %v\nSimplifying C: %v\n\n\n%s",
		stats.ExtractProgTime, stats.MinimizeProgTime,
		stats.SimplifyProgTime, stats.ExtractCTime, stats.SimplifyCTime, stats.Log))
}

func (repro *Result) CProgram() ([]byte, error) {
	cprog, err := csource.Write(repro.Prog, repro.Opts)
	if err == nil {
		formatted, err := csource.Format(cprog)
		if err == nil {
			return formatted, nil
		}
		return cprog, nil
	}
	return nil, err
}
