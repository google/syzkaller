// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	instancePkg "github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
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

type context struct {
	target       *targets.Target
	reporter     report.Reporter
	crashTitle   string
	crashType    report.Type
	instances    chan *instance
	bootRequests chan int
	timeouts     []time.Duration
	startOpts    csource.Options
	stats        *Stats
	report       *report.Report
}

type instance struct {
	*vm.Instance
	index       int
	execprogBin string
	executorBin string
}

func Run(crashLog []byte, cfg *mgrconfig.Config, features *host.Features, reporter report.Reporter,
	vmPool *vm.Pool, vmIndexes []int) (*Result, *Stats, error) {
	if len(vmIndexes) == 0 {
		return nil, nil, fmt.Errorf("no VMs provided")
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return nil, nil, err
	}
	entries := target.ParseLog(crashLog)
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("crash log does not contain any programs")
	}
	crashStart := len(crashLog)
	crashTitle, crashType := "", report.Unknown
	if rep := reporter.Parse(crashLog); rep != nil {
		crashStart = rep.StartPos
		crashTitle = rep.Title
		crashType = rep.Type
	}
	// The shortest duration is 10 seconds to detect simple crashes (i.e. no races and no hangs).
	// The longest duration is 6 minutes to catch races and hangs.
	noOutputTimeout := vm.NoOutputTimeout + time.Minute
	timeouts := []time.Duration{15 * time.Second, time.Minute, noOutputTimeout}
	switch {
	case crashTitle == "":
		crashTitle = "no output/lost connection"
		// Lost connection can be detected faster,
		// but theoretically if it's caused by a race it may need the largest timeout.
		// No output can only be reproduced with the max timeout.
		// As a compromise we use the smallest and the largest timeouts.
		timeouts = []time.Duration{15 * time.Second, noOutputTimeout}
	case crashType == report.MemoryLeak:
		// Memory leaks can't be detected quickly because of expensive setup and scanning.
		timeouts = []time.Duration{time.Minute, noOutputTimeout}
	case crashType == report.Hang:
		timeouts = []time.Duration{noOutputTimeout}
	}
	ctx := &context{
		target:       targets.Get(cfg.TargetOS, cfg.TargetArch),
		reporter:     reporter,
		crashTitle:   crashTitle,
		crashType:    crashType,
		instances:    make(chan *instance, len(vmIndexes)),
		bootRequests: make(chan int, len(vmIndexes)),
		timeouts:     timeouts,
		startOpts:    createStartOptions(cfg, features, crashType),
		stats:        new(Stats),
	}
	ctx.reproLogf(0, "%v programs, %v VMs, timeouts %v", len(entries), len(vmIndexes), timeouts)
	var wg sync.WaitGroup
	wg.Add(len(vmIndexes))
	for _, vmIndex := range vmIndexes {
		ctx.bootRequests <- vmIndex
		go func() {
			defer wg.Done()
			for vmIndex := range ctx.bootRequests {
				var inst *instance
				maxTry := 3
				for try := 0; try < maxTry; try++ {
					select {
					case <-vm.Shutdown:
						try = maxTry
						continue
					default:
					}
					var err error
					inst, err = ctx.initInstance(cfg, vmPool, vmIndex)
					if err != nil {
						ctx.reproLogf(0, "failed to init instance: %v", err)
						time.Sleep(10 * time.Second)
						continue
					}
					break
				}
				if inst == nil {
					break
				}
				ctx.instances <- inst
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ctx.instances)
	}()
	defer func() {
		close(ctx.bootRequests)
		for inst := range ctx.instances {
			inst.Close()
		}
	}()

	res, err := ctx.repro(entries, crashStart)
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

func createStartOptions(cfg *mgrconfig.Config, features *host.Features, crashType report.Type) csource.Options {
	opts := csource.DefaultOpts(cfg)
	if crashType == report.MemoryLeak {
		opts.Leak = true
	}
	if features != nil {
		if !features[host.FeatureNetInjection].Enabled {
			opts.NetInjection = false
		}
		if !features[host.FeatureNetDevices].Enabled {
			opts.NetDevices = false
		}
		if !features[host.FeatureDevlinkPCI].Enabled {
			opts.DevlinkPCI = false
		}
		if !features[host.FeatureUSBEmulation].Enabled {
			opts.USB = false
		}
		if !features[host.FeatureVhciInjection].Enabled {
			opts.VhciInjection = false
		}
	}
	return opts
}

func (ctx *context) initInstance(cfg *mgrconfig.Config, vmPool *vm.Pool, vmIndex int) (*instance, error) {
	vmInst, err := vmPool.Create(vmIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %v", err)
	}
	execprogBin, err := vmInst.Copy(cfg.SyzExecprogBin)
	if err != nil {
		vmInst.Close()
		return nil, fmt.Errorf("failed to copy to VM: %v", err)
	}
	executorCmd := ctx.target.SyzExecutorCmd
	if executorCmd == "" {
		executorCmd, err = vmInst.Copy(cfg.SyzExecutorBin)
		if err != nil {
			vmInst.Close()
			return nil, fmt.Errorf("failed to copy to VM: %v", err)
		}
	}
	return &instance{
		Instance:    vmInst,
		index:       vmIndex,
		execprogBin: execprogBin,
		executorBin: executorCmd,
	}, nil
}

func (ctx *context) repro(entries []*prog.LogEntry, crashStart int) (*Result, error) {
	// Cut programs that were executed after crash.
	for i, ent := range entries {
		if ent.Start > crashStart {
			entries = entries[:i]
			break
		}
	}

	reproStart := time.Now()
	defer func() {
		ctx.reproLogf(3, "reproducing took %s", time.Since(reproStart))
	}()

	res, err := ctx.extractProg(entries)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	defer func() {
		if res != nil {
			res.Opts.Repro = false
		}
	}()
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
	for _, timeout := range ctx.timeouts {
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
		opts.Fault = ent.Fault
		opts.FaultCall = ent.FaultCall
		opts.FaultNth = ent.FaultNth
		if opts.FaultCall < 0 || opts.FaultCall >= len(ent.P.Calls) {
			opts.FaultCall = len(ent.P.Calls) - 1
		}
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

	// Bisect the log to find multiple guilty programs.
	entries, err := ctx.bisectProgs(entries, func(progs []*prog.LogEntry) (bool, error) {
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
	prog := &prog.Prog{
		Target: entries[0].P.Target,
	}
	for _, entry := range entries {
		prog.Calls = append(prog.Calls, entry.P.Calls...)
	}
	dur := duration(len(entries)) * 3 / 2

	// Execute the program without fault injection.
	crashed, err := ctx.testProg(prog, dur, opts)
	if err != nil {
		return nil, err
	}
	if crashed {
		res := &Result{
			Prog:     prog,
			Duration: dur,
			Opts:     opts,
		}
		ctx.reproLogf(3, "bisect: concatenation succeeded")
		return res, nil
	}

	// Try with fault injection.
	calls := 0
	for _, entry := range entries {
		if entry.Fault {
			opts.FaultCall = calls + entry.FaultCall
			opts.FaultNth = entry.FaultNth
			if entry.FaultCall < 0 || entry.FaultCall >= len(entry.P.Calls) {
				opts.FaultCall = calls + len(entry.P.Calls) - 1
			}
			crashed, err := ctx.testProg(prog, dur, opts)
			if err != nil {
				return nil, err
			}
			if crashed {
				res := &Result{
					Prog:     prog,
					Duration: dur,
					Opts:     opts,
				}
				ctx.reproLogf(3, "bisect: concatenation succeeded with fault injection")
				return res, nil
			}
		}
		calls += len(entry.P.Calls)
	}

	ctx.reproLogf(3, "bisect: concatenation failed")
	return nil, nil
}

// Minimize calls and arguments.
func (ctx *context) minimizeProg(res *Result) (*Result, error) {
	ctx.reproLogf(2, "minimizing guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.MinimizeProgTime = time.Since(start)
	}()

	call := -1
	if res.Opts.Fault {
		call = res.Opts.FaultCall
	}
	res.Prog, res.Opts.FaultCall = prog.Minimize(res.Prog, call, true,
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

// Simplify repro options (threaded, collide, sandbox, etc).
func (ctx *context) simplifyProg(res *Result) (*Result, error) {
	ctx.reproLogf(2, "simplifying guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.SimplifyProgTime = time.Since(start)
	}()

	for _, simplify := range progSimplifies {
		opts := res.Opts
		if !simplify(&opts) {
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
		if simplify(&opts) {
			crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
			if err != nil {
				return nil, err
			}
			if crashed {
				res.Opts = opts
			}
		}
	}
	return res, nil
}

func (ctx *context) testProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	entry := prog.LogEntry{P: p}
	if opts.Fault {
		entry.Fault = true
		entry.FaultCall = opts.FaultCall
		entry.FaultNth = opts.FaultNth
	}
	return ctx.testProgs([]*prog.LogEntry{&entry}, duration, opts)
}

func (ctx *context) testProgs(entries []*prog.LogEntry, duration time.Duration, opts csource.Options) (
	crashed bool, err error) {
	inst := <-ctx.instances
	if inst == nil {
		return false, fmt.Errorf("all VMs failed to boot")
	}
	defer ctx.returnInstance(inst)
	if len(entries) == 0 {
		return false, fmt.Errorf("no programs to execute")
	}

	pstr := encodeEntries(entries)
	progFile, err := osutil.WriteTempFile(pstr)
	if err != nil {
		return false, err
	}
	defer os.Remove(progFile)
	vmProgFile, err := inst.Copy(progFile)
	if err != nil {
		return false, fmt.Errorf("failed to copy to VM: %v", err)
	}

	if !opts.Fault {
		opts.FaultCall = -1
	}
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

	command := instancePkg.ExecprogCmd(inst.execprogBin, inst.executorBin,
		ctx.target.OS, ctx.target.Arch, opts.Sandbox, opts.Repeat,
		opts.Threaded, opts.Collide, opts.Procs, -1, -1, vmProgFile)
	ctx.reproLogf(2, "testing program (duration=%v, %+v): %s", duration, opts, program)
	ctx.reproLogf(3, "detailed listing:\n%s", pstr)
	return ctx.testImpl(inst.Instance, command, duration)
}

func (ctx *context) testCProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	src, err := csource.Write(p, opts)
	if err != nil {
		return false, err
	}
	bin, err := csource.BuildNoWarn(p.Target, src)
	if err != nil {
		return false, err
	}
	defer os.Remove(bin)
	ctx.reproLogf(2, "testing compiled C program (duration=%v, %+v): %s", duration, opts, p)
	crashed, err = ctx.testBin(bin, duration)
	if err != nil {
		return false, err
	}
	return crashed, nil
}

func (ctx *context) testBin(bin string, duration time.Duration) (crashed bool, err error) {
	inst := <-ctx.instances
	if inst == nil {
		return false, fmt.Errorf("all VMs failed to boot")
	}
	defer ctx.returnInstance(inst)

	bin, err = inst.Copy(bin)
	if err != nil {
		return false, fmt.Errorf("failed to copy to VM: %v", err)
	}
	return ctx.testImpl(inst.Instance, bin, duration)
}

func (ctx *context) testImpl(inst *vm.Instance, command string, duration time.Duration) (crashed bool, err error) {
	outc, errc, err := inst.Run(duration, nil, command)
	if err != nil {
		return false, fmt.Errorf("failed to run command in VM: %v", err)
	}
	rep := inst.MonitorExecution(outc, errc, ctx.reporter,
		vm.ExitTimeout|vm.ExitNormal|vm.ExitError)
	if rep == nil {
		ctx.reproLogf(2, "program did not crash")
		return false, nil
	}
	if rep.Suppressed {
		ctx.reproLogf(2, "suppressed program crash: %v", rep.Title)
		return false, nil
	}
	if ctx.crashType == report.MemoryLeak && rep.Type != report.MemoryLeak {
		ctx.reproLogf(2, "not a leak crash: %v", rep.Title)
		return false, nil
	}
	ctx.report = rep
	ctx.reproLogf(2, "program crashed: %v", rep.Title)
	return true, nil
}

func (ctx *context) returnInstance(inst *instance) {
	ctx.bootRequests <- inst.index
	inst.Close()
}

func (ctx *context) reproLogf(level int, format string, args ...interface{}) {
	prefix := fmt.Sprintf("reproducing crash '%v': ", ctx.crashTitle)
	log.Logf(level, prefix+format, args...)
	ctx.stats.Log = append(ctx.stats.Log, []byte(fmt.Sprintf(format, args...)+"\n")...)
}

func (ctx *context) bisectProgs(progs []*prog.LogEntry, pred func([]*prog.LogEntry) (bool, error)) (
	[]*prog.LogEntry, error) {
	ctx.reproLogf(3, "bisect: bisecting %d programs", len(progs))

	ctx.reproLogf(3, "bisect: executing all %d programs", len(progs))
	crashed, err := pred(progs)
	if err != nil {
		return nil, err
	}
	if !crashed {
		ctx.reproLogf(3, "bisect: didn't crash")
		return nil, nil
	}

	guilty := [][]*prog.LogEntry{progs}
again:
	if len(guilty) > 8 {
		// This is usually the case for flaky crashes. Continuing bisection at this
		// point would just take a lot of time and likely produce no result.
		ctx.reproLogf(3, "bisect: too many guilty chunks, aborting")
		return nil, nil
	}
	ctx.reproLogf(3, "bisect: guilty chunks: %v", chunksToStr(guilty))
	for i, chunk := range guilty {
		if len(chunk) == 1 {
			continue
		}

		guilty1 := guilty[:i]
		guilty2 := guilty[i+1:]
		ctx.reproLogf(3, "bisect: guilty chunks split: %v, <%v>, %v",
			chunksToStr(guilty1), len(chunk), chunksToStr(guilty2))

		chunk1 := chunk[0 : len(chunk)/2]
		chunk2 := chunk[len(chunk)/2:]
		ctx.reproLogf(3, "bisect: chunk split: <%v> => <%v>, <%v>",
			len(chunk), len(chunk1), len(chunk2))

		ctx.reproLogf(3, "bisect: triggering crash without chunk #1")
		progs = flatenChunks(guilty1, guilty2, chunk2)
		crashed, err := pred(progs)
		if err != nil {
			return nil, err
		}

		if crashed {
			guilty = nil
			guilty = append(guilty, guilty1...)
			guilty = append(guilty, chunk2)
			guilty = append(guilty, guilty2...)
			ctx.reproLogf(3, "bisect: crashed, chunk #1 evicted")
			goto again
		}

		ctx.reproLogf(3, "bisect: triggering crash without chunk #2")
		progs = flatenChunks(guilty1, guilty2, chunk1)
		crashed, err = pred(progs)
		if err != nil {
			return nil, err
		}

		if crashed {
			guilty = nil
			guilty = append(guilty, guilty1...)
			guilty = append(guilty, chunk1)
			guilty = append(guilty, guilty2...)
			ctx.reproLogf(3, "bisect: crashed, chunk #2 evicted")
			goto again
		}

		guilty = nil
		guilty = append(guilty, guilty1...)
		guilty = append(guilty, chunk1)
		guilty = append(guilty, chunk2)
		guilty = append(guilty, guilty2...)

		ctx.reproLogf(3, "bisect: not crashed, both chunks required")

		goto again
	}

	progs = nil
	for _, chunk := range guilty {
		if len(chunk) != 1 {
			return nil, fmt.Errorf("bad bisect result: %v", guilty)
		}
		progs = append(progs, chunk[0])
	}

	ctx.reproLogf(3, "bisect: success, %d programs left", len(progs))
	return progs, nil
}

func flatenChunks(guilty1, guilty2 [][]*prog.LogEntry, chunk []*prog.LogEntry) []*prog.LogEntry {
	var progs []*prog.LogEntry
	for _, c := range guilty1 {
		progs = append(progs, c...)
	}
	progs = append(progs, chunk...)
	for _, c := range guilty2 {
		progs = append(progs, c...)
	}
	return progs
}

func chunksToStr(chunks [][]*prog.LogEntry) string {
	log := "["
	for i, chunk := range chunks {
		log += fmt.Sprintf("<%d>", len(chunk))
		if i != len(chunks)-1 {
			log += ", "
		}
	}
	log += "]"
	return log
}

func encodeEntries(entries []*prog.LogEntry) []byte {
	buf := new(bytes.Buffer)
	for _, ent := range entries {
		opts := ""
		if ent.Fault {
			opts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", ent.FaultCall, ent.FaultNth)
		}
		fmt.Fprintf(buf, "executing program %v%v:\n%v", ent.Proc, opts, string(ent.P.Serialize()))
	}
	return buf.Bytes()
}

type Simplify func(opts *csource.Options) bool

var progSimplifies = []Simplify{
	func(opts *csource.Options) bool {
		if !opts.Fault {
			return false
		}
		opts.Fault = false
		opts.FaultCall = 0
		opts.FaultNth = 0
		return true
	},
	func(opts *csource.Options) bool {
		if !opts.Collide {
			return false
		}
		opts.Collide = false
		return true
	},
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
		opts.USB = false
		opts.VhciInjection = false
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
}...)
