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
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig      = flag.String("config", "", "manager configuration file")
	flagDebug       = flag.Bool("debug", false, "dump all VM output to console")
	flagRestartTime = flag.Duration("restart_time", 0, "how long to run the test")
	flagInfinite    = flag.Bool("infinite", true, "by default test is run for ever, -infinite=false to stop on crash")
	flagStrace      = flag.Bool("strace", false, "run under strace (binary must be set in the config file")
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
	if *flagRestartTime == 0 {
		*flagRestartTime = cfg.Timeouts.VMRunningTime
	}
	if *flagInfinite {
		log.Printf("running infinitely and restarting VM every %v", *flagRestartTime)
	} else {
		log.Printf("running until crash is found or till %v", *flagRestartTime)
	}
	if *flagStrace && cfg.StraceBin == "" {
		log.Fatalf("strace_bin must not be empty in order to run with -strace")
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
		log.Printf("reproducing from C source file: %v", reproduceMe)
	} else {
		log.Printf("reproducing from log file: %v", reproduceMe)
	}
	log.Printf("booting %v test machines...", vmPool.Count())
	runDone := make(chan *instance.RunResult)
	var shutdown, stoppedWorkers uint32

	for i := 0; i < vmPool.Count(); i++ {
		go func(index int) {
			for {
				runDone <- runInstance(cfg, reporter, vmPool, index, *flagRestartTime, runType)
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

func storeCrash(cfg *mgrconfig.Config, res *instance.RunResult) {
	rep := res.Report
	id := hash.String([]byte(rep.Title))
	dir := filepath.Join(filepath.Dir(flag.Args()[0]), "crashes", id)
	osutil.MkdirAll(dir)

	index := 0
	for ; osutil.IsExist(filepath.Join(dir, fmt.Sprintf("log%v", index))); index++ {
	}
	log.Printf("saving crash '%v' with index %v in %v", rep.Title, index, dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Printf("failed to write crash description: %v", err)
	}
	if err := osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", index)), res.RawOutput); err != nil {
		log.Printf("failed to write crash log: %v", err)
	}
	if err := osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", index)), []byte(cfg.Tag)); err != nil {
		log.Printf("failed to write crash tag: %v", err)
	}
	if len(rep.Report) > 0 {
		if err := osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", index)), rep.Report); err != nil {
			log.Printf("failed to write crash report: %v", err)
		}
	}
	if err := osutil.CopyFile(flag.Args()[0], filepath.Join(dir, fmt.Sprintf("reproducer%v", index))); err != nil {
		log.Printf("failed to write crash reproducer: %v", err)
	}
}

func runInstance(cfg *mgrconfig.Config, reporter *report.Reporter,
	vmPool *vm.Pool, index int, timeout time.Duration, runType FileType) *instance.RunResult {
	log.Printf("vm-%v: starting", index)
	optArgs := &instance.OptionalConfig{
		ExitCondition: vm.ExitTimeout,
	}
	if *flagStrace {
		optArgs.StraceBin = cfg.StraceBin
	}
	var err error
	inst, err := instance.CreateExecProgInstance(vmPool, index, cfg, reporter, optArgs)
	if err != nil {
		log.Printf("failed to set up instance: %v", err)
		return nil
	}
	defer inst.VMInstance.Close()
	file := flag.Args()[0]
	var res *instance.RunResult
	if runType == LogFile {
		opts := csource.DefaultOpts(cfg)
		opts.Repeat, opts.Threaded = true, true
		res, err = inst.RunSyzProgFile(file, timeout, opts)
	} else {
		var src []byte
		src, err = ioutil.ReadFile(file)
		if err != nil {
			log.Fatalf("error reading source file from '%s'", file)
		}
		res, err = inst.RunCProgRaw(src, cfg.Target, timeout)
	}
	if err != nil {
		log.Printf("failed to execute program: %v", err)
		return nil
	}
	if res.Report != nil {
		log.Printf("vm-%v: crash: %v", index, res.Report.Title)
		return res
	}
	log.Printf("vm-%v: running long enough, stopping", index)
	return nil
}
