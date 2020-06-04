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
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig      = flag.String("config", "", "configuration file")
	flagRestartTime = flag.Duration("restartTime", 0, "restartPeriod how long to run the test.")
	flagInfinite    = flag.Bool("infinite", true, "by default test is run for ever. -infinite=false to stop on crash")
)

type CrashReport struct {
	vmIndex int
	Report  *report.Report
}

type FileType int

const (
	LogFile FileType = iota
	CProg
)

func getType(fileName string) FileType {
	extension := filepath.Ext(fileName)

	switch extension {
	case ".c":
		return CProg
	case ".txt", ".log":
		return LogFile
	default:
		log.Logf(0, "assuming logfile type")
		return LogFile
	}
}

func main() {
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
		os.Exit(1)
	}
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: syz-crush -config=config.file <execution.log|creprog.c>")
	}

	if err := osutil.MkdirAll(cfg.Workdir); err != nil {
		log.Fatalf("failed to create tmp dir: %v", err)
	}

	if *flagInfinite {
		log.Logf(0, "running infinitely and restarting VM every %v", *flagRestartTime)
	} else {
		log.Logf(0, "running until crash is found or till %v", *flagRestartTime)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
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

	reproduceMe := flag.Args()[0]
	baseName := filepath.Base(reproduceMe)

	runType := getType(reproduceMe)
	if runType == CProg {
		execprog, err := ioutil.ReadFile(reproduceMe)
		if err != nil {
			log.Fatalf("error reading source file from '%s'", reproduceMe)
		}

		cfg.SyzExecprogBin, err = csource.BuildNoWarn(target, execprog)
		if err != nil {
			log.Fatalf("failed to build source file: %v", err)
		}

		log.Logf(0, "compiled csource %v to cprog: %v", reproduceMe, cfg.SyzExecprogBin)
	} else {
		log.Logf(0, "reproducing from logfile: %v", reproduceMe)
	}

	restartPeriod := *flagRestartTime
	if restartPeriod == 0 {
		// Set default restart period to 1h
		restartPeriod = time.Hour
	}
	log.Logf(0, "restartTime set to: %v", *flagRestartTime)

	log.Logf(0, "booting test machines... %v", vmPool.Count())
	runDone := make(chan *CrashReport, vmPool.Count())
	var shutdown uint32
	var runningWorkers uint32

	for i := 0; i < vmPool.Count(); i++ {
		atomic.AddUint32(&runningWorkers, 1)
		go func(index int) {
			for {
				runDone <- runInstance(target, cfg, reporter, vmPool, index, *flagRestartTime,
					runType)
				if atomic.LoadUint32(&shutdown) != 0 || !*flagInfinite {
					atomic.AddUint32(&runningWorkers, ^uint32(0))

					// If this is the last worker then we can close the channel
					if atomic.LoadUint32(&runningWorkers) == 0 {
						log.Logf(0, "vm-%v: closing channel", index)
						close(runDone)
					}
					break
				} else {
					log.Logf(0, "vm-%v: restarting", index)
				}
			}
			log.Logf(0, "vm-%v: done", index)
		}(i)
	}

	log.Logf(0, "restart/timeout set to: %v", *flagRestartTime)
	shutdownC := make(chan struct{})
	osutil.HandleInterrupts(shutdownC)
	go func() {
		<-shutdownC
		atomic.StoreUint32(&shutdown, 1)
	}()

	var count int
	var crashes int
	for res := range runDone {
		count++
		crashes += storeCrash(res, cfg, baseName)
		log.Logf(0, "instances executed: %v", count)
	}

	log.Logf(0, "all done. reproduced %v crashes. reproduce rate %.2f%%", crashes, float64(crashes)/float64(count)*100.0)
}

func storeCrash(res *CrashReport, cfg *mgrconfig.Config, baseName string) int {
	log.Logf(0, "storing results...")
	if res == nil || res.Report == nil {
		log.Logf(0, "nothing to store")
		return 0
	}

	log.Logf(0, "loop: instance %v finished, crash=%v", res.vmIndex, res.Report.Title)

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	osutil.MkdirAll(crashdir)

	sig := hash.Hash([]byte(res.Report.Title))
	id := sig.String()
	dir := filepath.Join(crashdir, id)
	log.Logf(0, "vm-%v: crashed: %v, saving to %v", res.vmIndex, res.Report.Title, dir)

	osutil.MkdirAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(res.Report.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	// Save up to 100 reports. If we already have 100, overwrite the oldest one.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI := 0
	var oldestTime time.Time
	for i := 0; i < 100; i++ {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("log%v", i)))
		if err != nil {
			oldestI = i
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", oldestI)), res.Report.Output)
	if len(cfg.Tag) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", oldestI)), []byte(cfg.Tag))
	}
	if len(res.Report.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", oldestI)), res.Report.Report)
	}

	reproducedWithdir := filepath.Join(dir, "reproduced_with")
	osutil.MkdirAll(reproducedWithdir)
	if err := osutil.WriteFile(filepath.Join(reproducedWithdir, baseName), []byte(baseName+"\n")); err != nil {
		log.Logf(0, "failed to write reproducer: %v", err)
	}

	return 1
}

func runInstance(target *prog.Target, cfg *mgrconfig.Config, reporter report.Reporter,
	vmPool *vm.Pool, index int, timeout time.Duration, runType FileType) *CrashReport {
	inst, err := vmPool.Create(index)
	if err != nil {
		log.Logf(0, "failed to create instance: %v", err)
		return nil
	}
	defer inst.Close()

	execprogBin, err := inst.Copy(cfg.SyzExecprogBin)
	if err != nil {
		log.Logf(0, "failed to copy execprog: %v", err)
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
				log.Logf(0, "failed to copy executor: %v", err)
				return nil
			}
		}
		logFile, err := inst.Copy(flag.Args()[0])
		if err != nil {
			log.Logf(0, "failed to copy log: %v", err)
			return nil
		}

		cmd = instance.ExecprogCmd(execprogBin, executorCmd, cfg.TargetOS, cfg.TargetArch, cfg.Sandbox,
			true, true, true, cfg.Procs, -1, -1, logFile)
	} else {
		cmd = execprogBin
	}

	outc, errc, err := inst.Run(timeout, nil, cmd)
	if err != nil {
		log.Logf(0, "failed to run execprog: %v", err)
		return nil
	}

	log.Logf(0, "vm-%v: crushing...", index)
	rep := inst.MonitorExecution(outc, errc, reporter, vm.ExitTimeout)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "vm-%v: running long enough, stopping", index)
	}

	return &CrashReport{vmIndex: index, Report: rep}
}
