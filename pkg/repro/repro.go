// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/fileutil"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
)

type Result struct {
	Prog     *prog.Prog
	Duration time.Duration
	Opts     csource.Options
	CRepro   bool
}

type context struct {
	cfg          *mgrconfig.Config
	crashDesc    string
	instances    chan *instance
	bootRequests chan int
}

type instance struct {
	*vm.Instance
	index       int
	execprogBin string
	executorBin string
}

func reverseEntries(entries []*prog.LogEntry) []*prog.LogEntry {
	last := len(entries) - 1
	for i := 0; i < len(entries)/2; i++ {
		entries[i], entries[last-i] = entries[last-i], entries[i]
	}
	return entries
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
	Logf(0, "reproducing crash '%v': %v programs, %v VMs", crashDesc, len(entries), len(vmIndexes))

	ctx := &context{
		cfg:          cfg,
		crashDesc:    crashDesc,
		instances:    make(chan *instance, len(vmIndexes)),
		bootRequests: make(chan int, len(vmIndexes)),
	}
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
						Logf(0, "reproducing crash '%v': failed to create VM: %v", crashDesc, err)
						time.Sleep(10 * time.Second)
						continue

					}
					execprogBin, err := vmInst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-execprog"))
					if err != nil {
						Logf(0, "reproducing crash '%v': failed to copy to VM: %v", crashDesc, err)
						vmInst.Close()
						time.Sleep(10 * time.Second)
						continue
					}
					executorBin, err := vmInst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-executor"))
					if err != nil {
						Logf(0, "reproducing crash '%v': failed to copy to VM: %v", crashDesc, err)
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

	close(ctx.bootRequests)
	for inst := range ctx.instances {
		inst.Close()
	}
	return res, err
}

func (ctx *context) reproExtractProg(entries []*prog.LogEntry) (*Result, error) {
	Logf(2, "reproducing crash '%v': suspecting %v programs", ctx.crashDesc, len(entries))

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

	// Execute the suspected programs.
	// We first try to execute each program for 10 seconds, that should detect simple crashes
	// (i.e. no races and no hangs). Then we execute each program for 5 minutes
	// to catch races and hangs. Note that the max duration must be larger than
	// hang/no output detection duration in vm.MonitorExecution, which is currently set to 3 mins.
	// Programs are executed in reverse order, usually the last program is the guilty one.
	durations := []time.Duration{10 * time.Second, 5 * time.Minute}
	suspected := [][]*prog.LogEntry{reverseEntries(entries), reverseEntries(lastEntries)}
	var res *Result
	for i, dur := range durations {
		for _, ent := range suspected[i] {
			opts.Fault = ent.Fault
			opts.FaultCall = ent.FaultCall
			opts.FaultNth = ent.FaultNth
			if opts.FaultCall < 0 || opts.FaultCall >= len(ent.P.Calls) {
				opts.FaultCall = len(ent.P.Calls) - 1
			}
			crashed, err := ctx.testProg(ent.P, dur, opts)
			if err != nil {
				return nil, err
			}
			if crashed {
				res = &Result{
					Prog:     ent.P,
					Duration: dur * 3 / 2,
					Opts:     opts,
				}
				break
			}
		}
		if res != nil {
			break
		}
	}
	if res == nil {
		Logf(0, "reproducing crash '%v': no program crashed", ctx.crashDesc)
		return nil, nil
	}

	return res, nil
}

func (ctx *context) reproMinimizeProg(res *Result) (*Result, error) {
	Logf(2, "reproducing crash '%v': minimizing guilty program", ctx.crashDesc)

	// Minimize calls and arguments.
	call := -1
	if res.Opts.Fault {
		call = res.Opts.FaultCall
	}
	res.Prog, res.Opts.FaultCall = prog.Minimize(res.Prog, call, func(p1 *prog.Prog, callIndex int) bool {
		crashed, err := ctx.testProg(p1, res.Duration, res.Opts)
		if err != nil {
			Logf(1, "reproducing crash '%v': minimization failed with %v", ctx.crashDesc, err)
			return false
		}
		return crashed
	}, true)

	// Minimize repro options (threaded, collide, sandbox, etc).
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

func (ctx *context) reproExtractC(res *Result) (*Result, error) {
	Logf(2, "reproducing crash '%v': extracting C reproducer", ctx.crashDesc)

	// Try triggering crash with a C reproducer.
	crashed, err := ctx.testCProg(res.Prog, res.Duration, res.Opts)
	if err != nil {
		return res, err
	}
	res.CRepro = crashed
	return res, nil
}

func (ctx *context) reproMinimizeC(res *Result) (*Result, error) {
	Logf(2, "reproducing crash '%v': minimizing C reproducer", ctx.crashDesc)

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

func (ctx *context) repro(entries []*prog.LogEntry, crashStart int) (*Result, error) {
	// Cut programs that were executed after crash.
	for i, ent := range entries {
		if ent.Start > crashStart {
			entries = entries[:i]
			break
		}
	}

	res, err := ctx.reproExtractProg(entries)
	if err != nil {
		return res, err
	}
	if res == nil {
		return nil, nil
	}

	res, err = ctx.reproMinimizeProg(res)
	if err != nil {
		return res, err
	}

	res, err = ctx.reproExtractC(res)
	if err != nil {
		return res, err
	}
	if !res.CRepro {
		res.Opts.Repro = false
		return res, nil
	}

	res, err = ctx.reproMinimizeC(res)
	if err != nil {
		return res, err
	}

	res.Opts.Repro = false
	return res, nil
}

func (ctx *context) testProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	inst := <-ctx.instances
	if inst == nil {
		return false, fmt.Errorf("all VMs failed to boot")
	}
	defer ctx.returnInstance(inst)

	pstr := p.Serialize()
	progFile, err := fileutil.WriteTempFile(pstr)
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
	command := fmt.Sprintf("%v -executor %v -cover=0 -procs=%v -repeat=%v -sandbox %v -threaded=%v -collide=%v -fault_call=%v -fault_nth=%v %v",
		inst.execprogBin, inst.executorBin, opts.Procs, repeat, opts.Sandbox, opts.Threaded, opts.Collide, opts.FaultCall, opts.FaultNth, vmProgFile)
	Logf(2, "reproducing crash '%v': testing program (duration=%v, %+v): %s",
		ctx.crashDesc, duration, opts, p)
	return ctx.testImpl(inst.Instance, command, duration)
}

func (ctx *context) testCProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	src, err := csource.Write(p, opts)
	if err != nil {
		return false, err
	}
	srcf, err := fileutil.WriteTempFile(src)
	if err != nil {
		return false, err
	}
	bin, err := csource.Build("c", srcf)
	if err != nil {
		return false, err
	}
	defer os.Remove(bin)
	Logf(2, "reproducing crash '%v': testing compiled C program (duration=%v, %+v): %s",
		ctx.crashDesc, duration, opts, p)
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
	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, false, ctx.cfg.ParsedIgnores)
	_, _, _ = text, output, timedout
	if !crashed {
		Logf(2, "reproducing crash '%v': program did not crash", ctx.crashDesc)
		return false, nil
	}
	Logf(2, "reproducing crash '%v': program crashed: %v", ctx.crashDesc, desc)
	return true, nil
}

func (ctx *context) returnInstance(inst *instance) {
	ctx.bootRequests <- inst.index
	inst.Close()
}
