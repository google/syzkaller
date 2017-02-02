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

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/csource"
	"github.com/google/syzkaller/fileutil"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/report"
	"github.com/google/syzkaller/vm"
)

type Result struct {
	Prog   *prog.Prog
	Opts   csource.Options
	CRepro bool
}

type context struct {
	cfg          *config.Config
	crashDesc    string
	instances    chan *instance
	bootRequests chan int
}

type instance struct {
	vm.Instance
	index       int
	execprogBin string
	executorBin string
}

func Run(crashLog []byte, cfg *config.Config, vmIndexes []int) (*Result, error) {
	if len(vmIndexes) == 0 {
		return nil, fmt.Errorf("no VMs provided")
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-execprog")); err != nil {
		return nil, fmt.Errorf("bin/syz-execprog is missing (run 'make execprog')")
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
				for try := 0; try < 3; try++ {
					vmCfg, err := config.CreateVMConfig(cfg, vmIndex)
					if err != nil {
						Logf(0, "reproducing crash '%v': failed to create VM config: %v", crashDesc, err)
						time.Sleep(10 * time.Second)
						continue
					}
					vmInst, err := vm.Create(cfg.Type, vmCfg)
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
					inst = &instance{vmInst, vmIndex, execprogBin, executorBin}
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

func (ctx *context) repro(entries []*prog.LogEntry, crashStart int) (*Result, error) {
	// Cut programs that were executed after crash.
	for i, ent := range entries {
		if ent.Start > crashStart {
			entries = entries[:i]
			break
		}
	}
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
	var suspected []*prog.LogEntry
	for i := len(indices) - 1; i >= 0; i-- {
		suspected = append(suspected, entries[indices[i]])
	}
	Logf(2, "reproducing crash '%v': suspecting %v programs", ctx.crashDesc, len(suspected))
	opts := csource.Options{
		Threaded: true,
		Collide:  true,
		Repeat:   true,
		Procs:    ctx.cfg.Procs,
		Sandbox:  ctx.cfg.Sandbox,
		Repro:    true,
	}
	// Execute the suspected programs.
	// We first try to execute each program for 10 seconds, that should detect simple crashes
	// (i.e. no races and no hangs). Then we execute each program for 5 minutes
	// to catch races and hangs. Note that the max duration must be larger than
	// hang/no output detection duration in vm.MonitorExecution, which is currently set to 3 mins.
	var res *Result
	var duration time.Duration
	for _, dur := range []time.Duration{10 * time.Second, 5 * time.Minute} {
		for _, ent := range suspected {
			crashed, err := ctx.testProg(ent.P, dur, opts)
			if err != nil {
				return nil, err
			}
			if crashed {
				res = &Result{
					Prog: ent.P,
					Opts: opts,
				}
				duration = dur * 3 / 2
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
	defer func() {
		res.Opts.Repro = false
	}()

	Logf(2, "reproducing crash '%v': minimizing guilty program", ctx.crashDesc)
	res.Prog, _ = prog.Minimize(res.Prog, -1, func(p1 *prog.Prog, callIndex int) bool {
		crashed, err := ctx.testProg(p1, duration, res.Opts)
		if err != nil {
			Logf(1, "reproducing crash '%v': minimization failed with %v", ctx.crashDesc, err)
			return false
		}
		return crashed
	}, true)

	// Try to "minimize" threaded/collide/sandbox/etc to find simpler reproducer.
	opts = res.Opts
	opts.Collide = false
	crashed, err := ctx.testProg(res.Prog, duration, opts)
	if err != nil {
		return res, err
	}
	if crashed {
		res.Opts = opts
		opts.Threaded = false
		crashed, err := ctx.testProg(res.Prog, duration, opts)
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
		crashed, err := ctx.testProg(res.Prog, duration, opts)
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
		crashed, err := ctx.testProg(res.Prog, duration, opts)
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
		crashed, err := ctx.testProg(res.Prog, duration, opts)
		if err != nil {
			return res, err
		}
		if crashed {
			res.Opts = opts
		}
	}

	src, err := csource.Write(res.Prog, res.Opts)
	if err != nil {
		return res, err
	}
	srcf, err := fileutil.WriteTempFile(src)
	if err != nil {
		return res, err
	}
	bin, err := csource.Build("c", srcf)
	if err != nil {
		return res, err
	}
	defer os.Remove(bin)
	crashed, err = ctx.testBin(bin, duration)
	if err != nil {
		return res, err
	}
	res.CRepro = crashed
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

	repeat := "1"
	if opts.Repeat {
		repeat = "0"
	}
	command := fmt.Sprintf("%v -executor %v -cover=0 -procs=%v -repeat=%v -sandbox %v -threaded=%v -collide=%v %v",
		inst.execprogBin, inst.executorBin, opts.Procs, repeat, opts.Sandbox, opts.Threaded, opts.Collide, vmProgFile)
	Logf(2, "reproducing crash '%v': testing program (duration=%v, %+v): %s",
		ctx.crashDesc, duration, opts, p)
	return ctx.testImpl(inst, command, duration)
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
	Logf(2, "reproducing crash '%v': testing compiled C program", ctx.crashDesc)
	return ctx.testImpl(inst, bin, duration)
}

func (ctx *context) testImpl(inst vm.Instance, command string, duration time.Duration) (crashed bool, err error) {
	outc, errc, err := inst.Run(duration, nil, command)
	if err != nil {
		return false, fmt.Errorf("failed to run command in VM: %v", err)
	}
	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, false, false, ctx.cfg.ParsedIgnores)
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
