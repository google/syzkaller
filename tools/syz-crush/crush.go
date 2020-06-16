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
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig      = flag.String("config", "", "manager configuration file")
	flagDebug       = flag.Bool("debug", false, "dump all VM output to console")
	flagRestartTime = flag.Duration("restart_time", time.Hour, "how long to run the test")
	flagInfinite    = flag.Bool("infinite", true, "by default test is run for ever, -infinite=false to stop on crash")
)

type FileType int

const (
	LogFile FileType = iota
	CProg
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 || *flagConfig == "" {
		fmt.Fprintf(os.Stderr, "usage: syz-crush [flags] <execution.log|creprog.c>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatal(err)
	}

	if *flagInfinite {
		log.Printf("running infinitely and restarting VM every %v", *flagRestartTime)
	} else {
		log.Printf("running until crash is found or till %v", *flagRestartTime)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("%v", err)
	}

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	reproduceMe := flag.Args()[0]
	if cfg.Tag == "" {
		// If no tag is given, use reproducer name as the tag.
		cfg.Tag = filepath.Base(reproduceMe)
	}
	runType := LogFile
	if strings.HasSuffix(reproduceMe, ".c") {
		runType = CProg
	}
	if runType == CProg {
		execprog, err := ioutil.ReadFile(reproduceMe)
		if err != nil {
			log.Fatalf("error reading source file from '%s'", reproduceMe)
		}

		cfg.SyzExecprogBin, err = csource.BuildNoWarn(target, execprog)
		if err != nil {
			log.Fatalf("failed to build source file: %v", err)
		}

		log.Printf("compiled csource %v to cprog: %v", reproduceMe, cfg.SyzExecprogBin)
	} else {
		log.Printf("reproducing from log file: %v", reproduceMe)
	}

	log.Printf("booting %v test machines...", vmPool.Count())
	runDone := make(chan *report.Report)
	var shutdown, stoppedWorkers uint32

	for i := 0; i < vmPool.Count(); i++ {
		go func(index int) {
			for {
				runDone <- runInstance(target, cfg, reporter, vmPool, index, *flagRestartTime, runType)
				if atomic.LoadUint32(&shutdown) != 0 || !*flagInfinite {
					// If this is the last worker then we can close the channel.
					if atomic.AddUint32(&stoppedWorkers, 1) == uint32(vmPool.Count()) {
						log.Printf("vm-%v: closing channel", index)
						close(runDone)
					}
					break
				}
			}
			log.Printf("vm-%v: done", index)
		}(i)
	}

	shutdownC := make(chan struct{})
	osutil.HandleInterrupts(shutdownC)
	go func() {
		<-shutdownC
		atomic.StoreUint32(&shutdown, 1)
		close(vm.Shutdown)
	}()

	var count, crashes int
	for rep := range runDone {
		count++
		if rep != nil {
			crashes++
			storeCrash(cfg, rep)
		}
		log.Printf("instances executed: %v, crashes: %v", count, crashes)
	}

	log.Printf("all done. reproduced %v crashes. reproduce rate %.2f%%", crashes, float64(crashes)/float64(count)*100.0)
}

func storeCrash(cfg *mgrconfig.Config, rep *report.Report) {
	id := hash.String([]byte(rep.Title))
	dir := filepath.Join(cfg.Workdir, "crashes", id)
	osutil.MkdirAll(dir)
	log.Printf("saving crash %v to %v", rep.Title, dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Printf("failed to write crash description: %v", err)
	}
	index := 0
	for ; osutil.IsExist(filepath.Join(dir, fmt.Sprintf("log%v", index))); index++ {
	}
	osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", index)), rep.Output)
	osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", index)), []byte(cfg.Tag))
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", index)), rep.Report)
	}
}

func runInstance(target *prog.Target, cfg *mgrconfig.Config, reporter report.Reporter,
	vmPool *vm.Pool, index int, timeout time.Duration, runType FileType) *report.Report {
	log.Printf("vm-%v: starting", index)
	inst, err := vmPool.Create(index)
	if err != nil {
		log.Printf("failed to create instance: %v", err)
		return nil
	}
	defer inst.Close()

	execprogBin, err := inst.Copy(cfg.SyzExecprogBin)
	if err != nil {
		log.Printf("failed to copy execprog: %v", err)
		return nil
	}

	cmd := ""
	if runType == LogFile {
		// If SyzExecutorCmd is provided, it means that syz-executor is already in
		// the image, so no need to copy it.
		executorCmd := targets.Get(cfg.TargetOS, cfg.TargetArch).SyzExecutorCmd
		if executorCmd == "" {
			executorCmd, err = inst.Copy(cfg.SyzExecutorBin)
			if err != nil {
				log.Printf("failed to copy executor: %v", err)
				return nil
			}
		}
		logFile, err := inst.Copy(flag.Args()[0])
		if err != nil {
			log.Printf("failed to copy log: %v", err)
			return nil
		}

		cmd = instance.ExecprogCmd(execprogBin, executorCmd, cfg.TargetOS, cfg.TargetArch, cfg.Sandbox,
			true, true, true, cfg.Procs, -1, -1, logFile)
	} else {
		cmd = execprogBin
	}

	outc, errc, err := inst.Run(timeout, nil, cmd)
	if err != nil {
		log.Printf("failed to run execprog: %v", err)
		return nil
	}

	log.Printf("vm-%v: crushing...", index)
	rep := inst.MonitorExecution(outc, errc, reporter, vm.ExitTimeout)
	if rep != nil {
		log.Printf("vm-%v: crash: %v", index, rep.Title)
		return rep
	}
	log.Printf("vm-%v: running long enough, stopping", index)
	return nil
}
