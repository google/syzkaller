// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
)

type Stats struct {
	Log              []byte
	ExtractProgTime  time.Duration
	MinimizeProgTime time.Duration
	SimplifyProgTime time.Duration
	ExtractCTime     time.Duration
	SimplifyCTime    time.Duration
}

type Result struct {
	Prog     *prog.Prog
	Duration time.Duration
	Opts     csource.Options
	CRepro   bool
	Stats    Stats
	// Description and report of the final crash that we reproduced.
	// Can be different from what we started reproducing.
	Desc   string
	Report []byte
}

type context struct {
	cfg          *mgrconfig.Config
	crashDesc    string
	instances    chan *instance
	bootRequests chan int
	stats        Stats
	desc         string
	report       []byte
}

type instance struct {
	*vm.Instance
	index       int
	execprogBin string
	executorBin string
}

func Run(crashLog []byte, cfg *mgrconfig.Config, vmPool *vm.Pool, vmIndexes []int) (*Result, error) {
	if len(vmIndexes) == 0 {
		return nil, fmt.Errorf("no VMs provided")
	}
	entries := prog.ParseLog(crashLog)
	if len(entries) == 0 {
		return nil, fmt.Errorf("crash log does not contain any programs")
	}
	crashDesc, _, crashStart, _ := report.Parse(crashLog, cfg.ParsedIgnores)
	if crashDesc == "" {
		crashStart = len(crashLog) // assuming VM hanged
		crashDesc = "hang"
	}

	ctx := &context{
		cfg:          cfg,
		crashDesc:    crashDesc,
		instances:    make(chan *instance, len(vmIndexes)),
		bootRequests: make(chan int, len(vmIndexes)),
	}
	ctx.reproLog(0, "%v programs, %v VMs", len(entries), len(vmIndexes))
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
					vmInst, err := vmPool.Create(vmIndex)
					if err != nil {
						ctx.reproLog(0, "failed to create VM: %v", err)
						time.Sleep(10 * time.Second)
						continue

					}
					execprogBin, err := vmInst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-execprog"))
					if err != nil {
						ctx.reproLog(0, "failed to copy to VM: %v", err)
						vmInst.Close()
						time.Sleep(10 * time.Second)
						continue
					}
					executorBin, err := vmInst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-executor"))
					if err != nil {
						ctx.reproLog(0, "failed to copy to VM: %v", err)
						vmInst.Close()
						time.Sleep(10 * time.Second)
						continue
					}
					inst = &instance{
						Instance:    vmInst,
						index:       vmIndex,
						execprogBin: execprogBin,
						executorBin: executorBin,
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

	res, err := ctx.repro(entries, crashStart)
	if res != nil {
		ctx.reproLog(3, "repro crashed as:\n%s", string(ctx.report))
		res.Stats = ctx.stats
		res.Desc = ctx.desc
		res.Report = ctx.report
	}

	close(ctx.bootRequests)
	for inst := range ctx.instances {
		inst.Close()
	}
	return res, err
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
		ctx.reproLog(3, "reproducing took %s", time.Since(reproStart))
	}()

	res, err := ctx.extractProg(entries)
	if err != nil {
		return res, err
	}
	if res == nil {
		return nil, nil
	}

	res, err = ctx.minimizeProg(res)
	if err != nil {
		return res, err
	}

	res, err = ctx.simplifyProg(res)
	if err != nil {
		return res, err
	}

	res, err = ctx.extractC(res)
	if err != nil {
		return res, err
	}
	if !res.CRepro {
		res.Opts.Repro = false
		return res, nil
	}

	res, err = ctx.simplifyC(res)
	if err != nil {
		return res, err
	}

	res.Opts.Repro = false
	return res, nil
}

func (ctx *context) extractProg(entries []*prog.LogEntry) (*Result, error) {
	ctx.reproLog(2, "extracting reproducer from %v programs", len(entries))
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

	// The shortest duration is 10 seconds to detect simple crashes (i.e. no races and no hangs).
	// The longest duration is 5 minutes to catch races and hangs. Note that this value must be larger
	// than hang/no output detection duration in vm.MonitorExecution, which is currently set to 3 mins.
	timeouts := []time.Duration{10 * time.Second, 1 * time.Minute, 5 * time.Minute}

	for _, timeout := range timeouts {
		// Execute each program separately to detect simple crashes caused by a single program.
		// Programs are executed in reverse order, usually the last program is the guilty one.
		res, err := ctx.extractProgSingle(reverseEntries(lastEntries), timeout)
		if err != nil {
			return res, err
		}
		if res != nil {
			ctx.reproLog(3, "found reproducer with %d syscalls", len(res.Prog.Calls))
			return res, nil
		}

		// Execute all programs and bisect the log to find multiple guilty programs.
		res, err = ctx.extractProgBisect(reverseEntries(entries), timeout)
		if err != nil {
			return res, err
		}
		if res != nil {
			ctx.reproLog(3, "found reproducer with %d syscalls", len(res.Prog.Calls))
			return res, nil
		}
	}

	ctx.reproLog(0, "failed to extract reproducer")
	return nil, nil
}

func (ctx *context) extractProgSingle(entries []*prog.LogEntry, duration time.Duration) (*Result, error) {
	ctx.reproLog(3, "single: executing %d programs separately with timeout %s", len(entries), duration)

	opts := csource.Options{
		Threaded:   true,
		Collide:    true,
		Repeat:     true,
		Procs:      ctx.cfg.Procs,
		Sandbox:    ctx.cfg.Sandbox,
		EnableTun:  true,
		UseTmpDir:  true,
		HandleSegv: true,
		WaitRepeat: true,
		Debug:      true,
		Repro:      true,
	}

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
			ctx.reproLog(3, "single: successfully extracted reproducer")
			return res, nil
		}
	}

	ctx.reproLog(3, "single: failed to extract reproducer")
	return nil, nil
}

func (ctx *context) extractProgBisect(entries []*prog.LogEntry, baseDuration time.Duration) (*Result, error) {
	ctx.reproLog(3, "bisect: bisecting %d programs with base timeout %s", len(entries), baseDuration)

	opts := csource.Options{
		Threaded:   true,
		Collide:    true,
		Repeat:     true,
		Procs:      ctx.cfg.Procs,
		Sandbox:    ctx.cfg.Sandbox,
		EnableTun:  true,
		UseTmpDir:  true,
		HandleSegv: true,
		WaitRepeat: true,
		Debug:      true,
		Repro:      true,
	}

	duration := func(entries int) time.Duration {
		return baseDuration + time.Duration((entries/4))*time.Second
	}

	// Bisect the log to find multiple guilty programs.
	entries, err := ctx.bisectProgs(entries, func(progs []*prog.LogEntry) (bool, error) {
		return ctx.testProgs(progs, duration(len(progs)), opts)
	})
	if err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, nil
	}

	// TODO: Minimize each program before concatenation.
	// TODO: Return multiple programs if concatenation fails.

	ctx.reproLog(3, "bisect: %d programs left: \n\n%s\n", len(entries), encodeEntries(entries))
	ctx.reproLog(3, "bisect: trying to concatenate")

	// Concatenate all programs into one.
	var prog prog.Prog
	for _, entry := range entries {
		prog.Calls = append(prog.Calls, entry.P.Calls...)
	}

	// Execute the program without fault injection.
	dur := duration(len(entries)) * 3 / 2
	crashed, err := ctx.testProg(&prog, dur, opts)
	if err != nil {
		return nil, err
	}
	if crashed {
		res := &Result{
			Prog:     &prog,
			Duration: dur,
			Opts:     opts,
		}
		ctx.reproLog(3, "bisect: concatenation succeded")
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
			crashed, err := ctx.testProg(&prog, dur, opts)
			if err != nil {
				return nil, err
			}
			if crashed {
				res := &Result{
					Prog:     &prog,
					Duration: dur,
					Opts:     opts,
				}
				ctx.reproLog(3, "bisect: concatenation succeeded with fault injection")
				return res, nil
			}
		}
		calls += len(entry.P.Calls)
	}

	ctx.reproLog(3, "bisect: concatenation failed")
	return nil, nil
}

// Minimize calls and arguments.
func (ctx *context) minimizeProg(res *Result) (*Result, error) {
	ctx.reproLog(2, "minimizing guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.MinimizeProgTime = time.Since(start)
	}()

	call := -1
	if res.Opts.Fault {
		call = res.Opts.FaultCall
	}
	res.Prog, res.Opts.FaultCall = prog.Minimize(res.Prog, call, func(p1 *prog.Prog, callIndex int) bool {
		crashed, err := ctx.testProg(p1, res.Duration, res.Opts)
		if err != nil {
			ctx.reproLog(0, "minimization failed with %v", err)
			return false
		}
		return crashed
	}, true)

	return res, nil
}

// Simplify repro options (threaded, collide, sandbox, etc).
func (ctx *context) simplifyProg(res *Result) (*Result, error) {
	ctx.reproLog(2, "simplifying guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.SimplifyProgTime = time.Since(start)
	}()

	opts := res.Opts
	opts.Collide = false
	crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
	if err != nil {
		return res, err
	}
	if crashed {
		res.Opts = opts
		opts.Threaded = false
		crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.Sandbox == "namespace" {
		opts = res.Opts
		opts.Sandbox = "none"
		crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.Procs > 1 {
		opts = res.Opts
		opts.Procs = 1
		crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.Repeat {
		opts = res.Opts
		opts.Repeat = false
		crashed, err := ctx.testProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}

	return res, nil
}

func (ctx *context) extractC(res *Result) (*Result, error) {
	ctx.reproLog(2, "extracting C reproducer")
	start := time.Now()
	defer func() {
		ctx.stats.ExtractCTime = time.Since(start)
	}()

	// Try triggering crash with a C reproducer.
	crashed, err := ctx.testCProg(res.Prog, res.Duration, res.Opts)
	if err != nil {
		return res, err
	}
	res.CRepro = crashed
	return res, nil
}

func (ctx *context) simplifyC(res *Result) (*Result, error) {
	ctx.reproLog(2, "simplifying C reproducer")
	start := time.Now()
	defer func() {
		ctx.stats.SimplifyCTime = time.Since(start)
	}()

	// Try to simplify the C reproducer.
	if res.Opts.EnableTun {
		opts := res.Opts
		opts.EnableTun = false
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.Sandbox != "" {
		opts := res.Opts
		opts.Sandbox = ""
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.UseTmpDir {
		opts := res.Opts
		opts.UseTmpDir = false
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.HandleSegv {
		opts := res.Opts
		opts.HandleSegv = false
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.WaitRepeat {
		opts := res.Opts
		opts.WaitRepeat = false
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}
	if res.Opts.Debug {
		opts := res.Opts
		opts.Debug = false
		crashed, err := ctx.testCProg(res.Prog, res.Duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}

	return res, nil
}

func (ctx *context) testProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	entry := prog.LogEntry{P: p}
	if opts.FaultCall != -1 {
		entry.Fault = true
		entry.FaultCall = opts.FaultCall
		entry.FaultNth = opts.FaultNth
	}
	return ctx.testProgs([]*prog.LogEntry{&entry}, duration, opts)
}

func (ctx *context) testProgs(entries []*prog.LogEntry, duration time.Duration, opts csource.Options) (crashed bool, err error) {
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

	repeat := 1
	if opts.Repeat {
		repeat = 0
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
	command := fmt.Sprintf("%v -executor %v -cover=0 -procs=%v -repeat=%v -sandbox %v -threaded=%v -collide=%v %v",
		inst.execprogBin, inst.executorBin, opts.Procs, repeat, opts.Sandbox, opts.Threaded, opts.Collide, vmProgFile)
	ctx.reproLog(2, "testing program (duration=%v, %+v): %s", duration, opts, program)
	return ctx.testImpl(inst.Instance, command, duration)
}

func (ctx *context) testCProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	src, err := csource.Write(p, opts)
	if err != nil {
		return false, err
	}
	srcf, err := osutil.WriteTempFile(src)
	if err != nil {
		return false, err
	}
	bin, err := csource.Build("c", srcf)
	if err != nil {
		return false, err
	}
	defer os.Remove(bin)
	ctx.reproLog(2, "testing compiled C program (duration=%v, %+v): %s", duration, opts, p)
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
	desc, report, output, crashed, timedout := vm.MonitorExecution(outc, errc, false, ctx.cfg.ParsedIgnores)
	_, _, _ = report, output, timedout
	if !crashed {
		ctx.reproLog(2, "program did not crash")
		return false, nil
	}
	ctx.desc = desc
	ctx.report = report
	ctx.reproLog(2, "program crashed: %v", desc)
	return true, nil
}

func (ctx *context) returnInstance(inst *instance) {
	ctx.bootRequests <- inst.index
	inst.Close()
}

func (ctx *context) reproLog(level int, format string, args ...interface{}) {
	prefix := fmt.Sprintf("reproducing crash '%v': ", ctx.crashDesc)
	Logf(level, prefix+format, args...)
	ctx.stats.Log = append(ctx.stats.Log, []byte(fmt.Sprintf(format, args...)+"\n")...)
}

func (ctx *context) bisectProgs(progs []*prog.LogEntry, pred func([]*prog.LogEntry) (bool, error)) ([]*prog.LogEntry, error) {
	ctx.reproLog(3, "bisect: bisecting %d programs", len(progs))

	compose := func(guilty1, guilty2 [][]*prog.LogEntry, chunk []*prog.LogEntry) []*prog.LogEntry {
		progs := []*prog.LogEntry{}
		for _, c := range guilty1 {
			progs = append(progs, c...)
		}
		progs = append(progs, chunk...)
		for _, c := range guilty2 {
			progs = append(progs, c...)
		}
		return progs
	}

	logGuilty := func(guilty [][]*prog.LogEntry) string {
		log := "["
		for i, chunk := range guilty {
			log += fmt.Sprintf("<%d>", len(chunk))
			if i != len(guilty)-1 {
				log += ", "
			}
		}
		log += "]"
		return log
	}

	ctx.reproLog(3, "bisect: executing all %d programs", len(progs))
	crashed, err := pred(progs)
	if err != nil {
		return nil, err
	}
	if !crashed {
		ctx.reproLog(3, "bisect: didn't crash")
		return nil, nil
	}

	guilty := [][]*prog.LogEntry{progs}
again:
	ctx.reproLog(3, "bisect: guilty chunks: %v", logGuilty(guilty))
	for i, chunk := range guilty {
		if len(chunk) == 1 {
			continue
		}

		guilty1 := guilty[:i]
		guilty2 := guilty[i+1:]
		ctx.reproLog(3, "bisect: guilty chunks split: %v, <%v>, %v", logGuilty(guilty1), len(chunk), logGuilty(guilty2))

		chunk1 := chunk[0 : len(chunk)/2]
		chunk2 := chunk[len(chunk)/2 : len(chunk)]
		ctx.reproLog(3, "bisect: chunk split: <%v> => <%v>, <%v>", len(chunk), len(chunk1), len(chunk2))

		ctx.reproLog(3, "bisect: triggering crash without chunk #1")
		progs := compose(guilty1, guilty2, chunk2)
		crashed, err := pred(progs)
		if err != nil {
			return nil, err
		}

		if crashed {
			guilty = nil
			guilty = append(guilty, guilty1...)
			guilty = append(guilty, chunk2)
			guilty = append(guilty, guilty2...)
			ctx.reproLog(3, "bisect: crashed, chunk #1 evicted")
			goto again
		}

		ctx.reproLog(3, "bisect: triggering crash without chunk #2")
		progs = compose(guilty1, guilty2, chunk1)
		crashed, err = pred(progs)
		if err != nil {
			return nil, err
		}

		if crashed {
			guilty = nil
			guilty = append(guilty, guilty1...)
			guilty = append(guilty, chunk1)
			guilty = append(guilty, guilty2...)
			ctx.reproLog(3, "bisect: crashed, chunk #2 evicted")
			goto again
		}

		guilty = nil
		guilty = append(guilty, guilty1...)
		guilty = append(guilty, chunk1)
		guilty = append(guilty, chunk2)
		guilty = append(guilty, guilty2...)

		ctx.reproLog(3, "bisect: not crashed, both chunks required")

		goto again
	}

	progs = nil
	for _, chunk := range guilty {
		if len(chunk) != 1 {
			return nil, fmt.Errorf("bad bisect result: %v", guilty)
		}
		progs = append(progs, chunk[0])
	}

	ctx.reproLog(3, "bisect: success, %d programs left", len(progs))
	return progs, nil
}

func reverseEntries(entries []*prog.LogEntry) []*prog.LogEntry {
	last := len(entries) - 1
	for i := 0; i < len(entries)/2; i++ {
		entries[i], entries[last-i] = entries[last-i], entries[i]
	}
	return entries
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
