// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// package main starts the syz-verifier tool. High-level documentation can be
// found in docs/syz_verifier.md.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
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
func Setup(name string, cfg *mgrconfig.Config, debug bool) (*Kernel, error) {
	kernel := &Kernel{
		name:            name,
		debug:           debug,
		cfg:             cfg,
		crashes:         make(chan *report.Report, 128),
		servStats:       rpcserver.NewNamedStats(name),
		candidates:      make(chan []fuzzer.Candidate),
		reportGenerator: manager.ReportGeneratorCache(cfg),
		enabledSyscalls: make(chan map[*prog.Syscall]bool, 1),
		features:        make(chan flatrpc.Feature, 1),
	}
	var err error
	kernel.reporter, err = report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter for %q: %w", name, err)
	}

	kernel.serv, err = rpcserver.New(&rpcserver.RemoteConfig{
		Config:  cfg,
		Manager: kernel,
		Stats:   kernel.servStats,
		Debug:   debug,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc server for %q: %w", name, err)
	}

	vmPool, err := vm.Create(cfg, debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm.Pool for %q: %w", name, err)
	}

	kernel.pool = vm.NewDispatcher(vmPool, kernel.FuzzerInstance)
	return kernel, nil
}

func main() {
	var cfgs tool.CfgsFlag
	flag.Var(&cfgs, "configs", "[MANDATORY] list of at least two kernel-specific comma-sepatated configuration files")
	flagDebug := flag.Bool("debug", false, "dump all VM output to console")
	// flagAddress := flag.String("address", "127.0.0.1:8080", "http address for monitoring")
	// flagReruns := flag.Int("rerun", 3, "number of time program is rerun when a mismatch is found")
	flag.Parse()

	kernels := make(map[int]*Kernel)
	for idx, cfg := range cfgs {
		kcfg, err := mgrconfig.LoadFile(cfg)
		if err != nil {
			log.Fatalf("%v", err)
		}
		kernels[idx], err = Setup(kcfg.Name, kcfg, *flagDebug)
		if err != nil {
			log.Fatalf("failed to setup kcfg context for %s: %v", kcfg.Name, err)
		}

		log.Logf(0, "loaded kernel %s", kcfg.Name)
	}

	log.Logf(0, "loaded %d kernel configurations", len(kernels))
	if len(kernels) < 2 && !*flagDebug {
		flag.Usage()
		os.Exit(1)
	}
	workdir := kernels[0].cfg.Workdir
	reqMaxSignal := make(chan int, len(kernels))
	sources := make(map[int]*queue.PlainQueue)
	for idx, kernel := range kernels {
		if kernel.cfg.Workdir != workdir {
			log.Fatalf("all kernel configurations must have the same workdir, got %q and %q", workdir, kernel.cfg.Workdir)
		}
		kernel.reqMaxSignal = reqMaxSignal
		sources[idx] = queue.Plain()
		kernel.source = sources[idx]
	}
	osutil.MkdirAll(workdir)

	log.Logf(0, "initialized %d sources", len(sources))

	vrf := &Verifier{
		kernels:        kernels,
		cfg:            kernels[0].cfg, // for now take the first kernel's config
		corpusPreload:  make(chan []fuzzer.Candidate),
		disabledHashes: make(map[string]struct{}),
		target:         kernels[0].cfg.Target,
		sources:        sources,
	}

	ctx := vm.ShutdownCtx()
	vrf.RunVerifierFuzzer(ctx)

}
