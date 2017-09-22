// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-crush replays crash log on multiple VMs. Usage:
//   syz-crush -config=config.file execution.log
// Intended for reproduction of particularly elusive crashes.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
)

func main() {
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		Fatalf("%v", err)
	}
	if len(flag.Args()) != 1 {
		Fatalf("usage: syz-crush -config=config.file execution.log")
	}
	if _, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch); err != nil {
		Fatalf("%v", err)
	}
	env := mgrconfig.CreateVMEnv(cfg, false)
	vmPool, err := vm.Create(cfg.Type, env)
	if err != nil {
		Fatalf("%v", err)
	}

	Logf(0, "booting test machines...")
	var shutdown uint32
	var wg sync.WaitGroup
	wg.Add(vmPool.Count() + 1)
	for i := 0; i < vmPool.Count(); i++ {
		i := i
		go func() {
			defer wg.Done()
			for {
				runInstance(cfg, vmPool, i)
				if atomic.LoadUint32(&shutdown) != 0 {
					break
				}
			}
		}()
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		wg.Done()
		atomic.StoreUint32(&shutdown, 1)
		close(vm.Shutdown)
		Logf(-1, "shutting down...")
		atomic.StoreUint32(&shutdown, 1)
		<-c
		Fatalf("terminating")
	}()
	wg.Wait()
}

func runInstance(cfg *mgrconfig.Config, vmPool *vm.Pool, index int) {
	inst, err := vmPool.Create(index)
	if err != nil {
		Logf(0, "failed to create instance: %v", err)
		return
	}
	defer inst.Close()

	execprogBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin", "syz-execprog"))
	if err != nil {
		Logf(0, "failed to copy execprog: %v", err)
		return
	}
	executorBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin", "syz-executor"))
	if err != nil {
		Logf(0, "failed to copy executor: %v", err)
		return
	}
	logFile, err := inst.Copy(flag.Args()[0])
	if err != nil {
		Logf(0, "failed to copy log: %v", err)
		return
	}

	cmd := fmt.Sprintf("%v -executor=%v -repeat=0 -procs=%v -cover=0 -sandbox=%v %v",
		execprogBin, executorBin, cfg.Procs, cfg.Sandbox, logFile)
	outc, errc, err := inst.Run(time.Hour, nil, cmd)
	if err != nil {
		Logf(0, "failed to run execprog: %v", err)
		return
	}

	Logf(0, "vm-%v: crushing...", index)
	desc, _, output, crashed, timedout := vm.MonitorExecution(outc, errc, true, cfg.ParsedIgnores)
	if timedout {
		// This is the only "OK" outcome.
		Logf(0, "vm-%v: running long enough, restarting", index)
	} else {
		if !crashed {
			// syz-execprog exited, but it should not.
			desc = "lost connection to test machine"
		}
		f, err := ioutil.TempFile(".", "syz-crush")
		if err != nil {
			Logf(0, "failed to create temp file: %v", err)
			return
		}
		defer f.Close()
		Logf(0, "vm-%v: crashed: %v, saving to %v", index, desc, f.Name())
		f.Write(output)
	}
	return
}
