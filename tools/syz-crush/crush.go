// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-crush replays crash log on multiple VMs. Usage:
//   syz-crush -config=config.file execution.log
// Intended for reproduction of particularly elusive crashes.
package main

import (
	"flag"
	"io/ioutil"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
)

func main() {
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: syz-crush -config=config.file execution.log")
	}
	if _, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch); err != nil {
		log.Fatalf("%v", err)
	}
	vmPool, err := vm.Create(cfg, false)
	if err != nil {
		log.Fatalf("%v", err)
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Logf(0, "booting test machines...")
	var shutdown uint32
	var wg sync.WaitGroup
	wg.Add(vmPool.Count() + 1)
	for i := 0; i < vmPool.Count(); i++ {
		i := i
		go func() {
			defer wg.Done()
			for {
				runInstance(cfg, reporter, vmPool, i)
				if atomic.LoadUint32(&shutdown) != 0 {
					break
				}
			}
		}()
	}

	shutdownC := make(chan struct{})
	osutil.HandleInterrupts(shutdownC)
	go func() {
		<-shutdownC
		wg.Done()
		atomic.StoreUint32(&shutdown, 1)
	}()
	wg.Wait()
}

func runInstance(cfg *mgrconfig.Config, reporter report.Reporter, vmPool *vm.Pool, index int) {
	inst, err := vmPool.Create(index)
	if err != nil {
		log.Logf(0, "failed to create instance: %v", err)
		return
	}
	defer inst.Close()

	execprogBin, err := inst.Copy(cfg.SyzExecprogBin)
	if err != nil {
		log.Logf(0, "failed to copy execprog: %v", err)
		return
	}
	executorBin, err := inst.Copy(cfg.SyzExecutorBin)
	if err != nil {
		log.Logf(0, "failed to copy executor: %v", err)
		return
	}
	logFile, err := inst.Copy(flag.Args()[0])
	if err != nil {
		log.Logf(0, "failed to copy log: %v", err)
		return
	}

	cmd := instance.ExecprogCmd(execprogBin, executorBin, cfg.TargetOS, cfg.TargetArch, cfg.Sandbox,
		true, true, true, cfg.Procs, -1, -1, logFile)
	outc, errc, err := inst.Run(time.Hour, nil, cmd)
	if err != nil {
		log.Logf(0, "failed to run execprog: %v", err)
		return
	}

	log.Logf(0, "vm-%v: crushing...", index)
	rep := inst.MonitorExecution(outc, errc, reporter, vm.ExitTimeout)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "vm-%v: running long enough, restarting", index)
	} else {
		f, err := ioutil.TempFile(".", "syz-crush")
		if err != nil {
			log.Logf(0, "failed to create temp file: %v", err)
			return
		}
		defer f.Close()
		log.Logf(0, "vm-%v: crashed: %v, saving to %v", index, rep.Title, f.Name())
		f.Write(rep.Output)
	}
}
