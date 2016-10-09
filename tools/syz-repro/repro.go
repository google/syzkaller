// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/csource"
	"github.com/google/syzkaller/fileutil"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/report"
	"github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/gce"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/qemu"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagCount  = flag.Int("count", 0, "number of VMs to use (overrides config count param)")

	instances    chan VM
	bootRequests chan int
	shutdown     = make(chan struct{})
)

type VM struct {
	vm.Instance
	index       int
	execprogBin string
	executorBin string
}

func main() {
	flag.Parse()
	cfg, _, _, err := config.Parse(*flagConfig)
	if err != nil {
		Fatalf("%v", err)
	}
	if *flagCount > 0 {
		cfg.Count = *flagCount
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-execprog")); err != nil {
		Fatalf("bin/syz-execprog is missing (run 'make execprog')")
	}

	if len(flag.Args()) != 1 {
		Fatalf("usage: syz-repro -config=config.file execution.log")
	}
	data, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		Fatalf("failed to open log file: %v", err)
	}
	entries := prog.ParseLog(data)
	Logf(0, "parsed %v programs", len(entries))

	crashDesc, _, crashStart, _ := report.Parse(data)
	if crashDesc == "" {
		crashStart = len(data) // assuming VM hanged
	}

	instances = make(chan VM, cfg.Count)
	bootRequests = make(chan int, cfg.Count)
	for i := 0; i < cfg.Count; i++ {
		bootRequests <- i
		go func() {
			for index := range bootRequests {
				vmCfg, err := config.CreateVMConfig(cfg, index)
				if err != nil {
					Fatalf("failed to create VM config: %v", err)
				}
				inst, err := vm.Create(cfg.Type, vmCfg)
				if err != nil {
					Fatalf("failed to create VM: %v", err)
				}
				execprogBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-execprog"))
				if err != nil {
					Fatalf("failed to copy to VM: %v", err)
				}
				executorBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin/syz-executor"))
				if err != nil {
					Fatalf("failed to copy to VM: %v", err)
				}
				instances <- VM{inst, index, execprogBin, executorBin}
			}
		}()
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		close(shutdown)
		Logf(-1, "shutting down...")
		<-c
		Fatalf("terminating")
	}()

	repro(cfg, entries, crashStart)
	exit()
}

func exit() {
	for {
		select {
		case inst := <-instances:
			inst.Close()
		default:
			os.Exit(0)
		}
	}
}

func repro(cfg *config.Config, entries []*prog.LogEntry, crashStart int) {
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
	// Execute the suspected programs.
	Logf(0, "the suspected programs are:")
	for _, ent := range suspected {
		Logf(0, "on proc %v:\n%s\n", ent.Proc, ent.P.Serialize())
	}
	var p *prog.Prog
	multiplier := 1
	for ; p == nil && multiplier <= 100; multiplier *= 10 {
		for _, ent := range suspected {
			if testProg(cfg, ent.P, multiplier, true, true) {
				p = ent.P
				break
			}
		}
	}
	if p == nil {
		Logf(0, "no program crashed")
		return
	}
	Logf(0, "minimizing program")

	p, _ = prog.Minimize(p, -1, func(p1 *prog.Prog, callIndex int) bool {
		return testProg(cfg, p1, multiplier, true, true)
	})

	opts := csource.Options{
		Threaded: true,
		Collide:  true,
	}
	if testProg(cfg, p, multiplier, true, false) {
		opts.Collide = false
		if testProg(cfg, p, multiplier, false, false) {
			opts.Threaded = false
		}
	}

	src := csource.Write(p, opts)
	src, _ = csource.Format(src)
	Logf(0, "C source:\n%s\n", src)
	srcf, err := fileutil.WriteTempFile(src)
	if err != nil {
		Fatalf("%v", err)
	}
	bin, err := csource.Build(srcf)
	if err != nil {
		Fatalf("%v", err)
	}
	defer os.Remove(bin)
	testBin(cfg, bin)
}

func returnInstance(inst VM, res bool) {
	if res {
		// The test crashed, discard the VM and issue another boot request.
		bootRequests <- inst.index
		inst.Close()
	} else {
		// The test did not crash, reuse the same VM in future.
		instances <- inst
	}
}

func testProg(cfg *config.Config, p *prog.Prog, multiplier int, threaded, collide bool) (res bool) {
	Logf(0, "booting VM")
	var inst VM
	select {
	case inst = <-instances:
	case <-shutdown:
		exit()
	}
	defer func() {
		returnInstance(inst, res)
	}()

	pstr := p.Serialize()
	progFile, err := fileutil.WriteTempFile(pstr)
	if err != nil {
		Fatalf("%v", err)
	}
	defer os.Remove(progFile)
	bin, err := inst.Copy(progFile)
	if err != nil {
		Fatalf("failed to copy to VM: %v", err)
	}

	repeat := 100
	timeoutSec := 10 * repeat / cfg.Procs
	if threaded {
		repeat *= 10
		timeoutSec *= 1
	}
	repeat *= multiplier
	timeoutSec *= multiplier
	timeout := time.Duration(timeoutSec) * time.Second
	command := fmt.Sprintf("%v -executor %v -cover=0 -procs=%v -repeat=%v -sandbox %v -threaded=%v -collide=%v %v",
		inst.execprogBin, inst.executorBin, cfg.Procs, repeat, cfg.Sandbox, threaded, collide, bin)
	Logf(0, "testing program (threaded=%v, collide=%v, repeat=%v, timeout=%v):\n%s\n",
		threaded, collide, repeat, timeout, pstr)
	return testImpl(inst, command, timeout)
}

func testBin(cfg *config.Config, bin string) (res bool) {
	Logf(0, "booting VM")
	var inst VM
	select {
	case inst = <-instances:
	case <-shutdown:
		exit()
	}
	defer func() {
		returnInstance(inst, res)
	}()

	bin, err := inst.Copy(bin)
	if err != nil {
		Fatalf("failed to copy to VM: %v", err)
	}
	Logf(0, "testing compiled C program")
	return testImpl(inst, bin, 10*time.Second)
}

func testImpl(inst vm.Instance, command string, timeout time.Duration) (res bool) {
	outc, errc, err := inst.Run(timeout, command)
	if err != nil {
		Fatalf("failed to run command in VM: %v", err)
	}
	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, false, false)
	_, _ = text, output
	if crashed || timedout {
		Logf(0, "program crashed with: %v", desc)
		return true
	}
	Logf(0, "program did not crash")
	return false
}
