// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

// package main starts the syz-verifier tool. High-level documentation can be
// found in docs/syz_verifier.md.
package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

const (
	maxResultReports = 100
)

// poolInfo contains kernel-specific information for spawning virtual machines
// and reporting crashes. It also keeps track of the Runners executing on
// spawned VMs, what programs have been sent to each Runner and what programs
// have yet to be sent on any of the Runners.
type poolInfo struct {
	cfg      *mgrconfig.Config
	pool     *vm.Pool
	Reporter *report.Reporter
	// checked is set to true when the set of system calls not supported on the
	// kernel is known.
	checked bool
}

func main() {
	var cfgs tool.CfgsFlag
	flag.Var(&cfgs, "configs", "[MANDATORY] list of at least two kernel-specific comma-sepatated configuration files")
	flagDebug := flag.Bool("debug", false, "dump all VM output to console")
	flagStats := flag.String("stats", "", "where stats will be written when"+
		"execution of syz-verifier finishes, defaults to stdout")
	flagEnv := flag.Bool("new-env", true, "create a new environment for each program")
	flagAddress := flag.String("address", "127.0.0.1:8080", "http address for monitoring")
	flagReruns := flag.Int("rerun", 3, "number of time program is rerun when a mismatch is found")
	flag.Parse()

	pools := make(map[int]*poolInfo)
	for idx, cfg := range cfgs {
		var err error
		pi := &poolInfo{}
		pi.cfg, err = mgrconfig.LoadFile(cfg)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pi.pool, err = vm.Create(pi.cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pools[idx] = pi
	}

	if len(pools) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	cfg := pools[0].cfg
	workdir, target, sysTarget, addr := cfg.Workdir, cfg.Target, cfg.SysTarget, cfg.RPC
	for idx := 1; idx < len(pools); idx++ {
		cfg := pools[idx].cfg

		// TODO: pass the configurations that should be the same for all
		// kernels in a default config file in order to avoid this checks and
		// add testing
		if workdir != cfg.Workdir {
			log.Fatalf("working directory mismatch")
		}
		if target != cfg.Target {
			log.Fatalf("target mismatch")
		}
		if sysTarget != cfg.SysTarget {
			log.Fatalf("system target mismatch")
		}
		if addr != pools[idx].cfg.RPC {
			log.Fatalf("tcp address mismatch")
		}
	}

	exe := sysTarget.ExeExtension
	runnerBin := filepath.Join(cfg.Syzkaller, "bin", target.OS+"_"+target.Arch, "syz-runner"+exe)
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", runnerBin)
	}
	execBin := cfg.ExecutorBin
	if !osutil.IsExist(execBin) {
		log.Fatalf("bad syzkaller config: can't find %v", execBin)
	}

	crashdir := filepath.Join(workdir, "crashes")
	osutil.MkdirAll(crashdir)
	for idx := range pools {
		OS, Arch := target.OS, target.Arch
		targetPath := OS + "-" + Arch + "-" + strconv.Itoa(idx)
		osutil.MkdirAll(filepath.Join(workdir, targetPath))
		osutil.MkdirAll(filepath.Join(crashdir, targetPath))
	}

	resultsdir := filepath.Join(workdir, "results")
	osutil.MkdirAll(resultsdir)

	var sw io.Writer
	var err error
	if *flagStats == "" {
		sw = os.Stdout
	} else {
		statsFile := filepath.Join(workdir, *flagStats)
		sw, err = os.Create(statsFile)
		if err != nil {
			log.Fatalf("failed to create stats output file: %v", err)
		}
	}

	for idx, pi := range pools {
		var err error
		pi.Reporter, err = report.NewReporter(pi.cfg)
		if err != nil {
			log.Fatalf("failed to create reporter for instance-%d: %v", idx, err)
		}
	}

	calls := make(map[*prog.Syscall]bool)

	for _, id := range cfg.Syscalls {
		c := target.Syscalls[id]
		calls[c] = true
	}

	vrf := &Verifier{
		workdir:       workdir,
		crashdir:      crashdir,
		resultsdir:    resultsdir,
		pools:         pools,
		target:        target,
		calls:         calls,
		reasons:       make(map[*prog.Syscall]string),
		runnerBin:     runnerBin,
		executorBin:   execBin,
		addr:          addr,
		reportReasons: len(cfg.EnabledSyscalls) != 0 || len(cfg.DisabledSyscalls) != 0,
		stats:         MakeStats(),
		statsWrite:    sw,
		newEnv:        *flagEnv,
		reruns:        *flagReruns,
	}

	vrf.Init()

	vrf.StartProgramsAnalysis()
	vrf.startInstances()

	monitor := MakeMonitor()
	monitor.SetStatsTracking(vrf.stats)

	log.Logf(0, "run the Monitor at http://%s", *flagAddress)
	go monitor.ListenAndServe(*flagAddress)

	select {}
}
