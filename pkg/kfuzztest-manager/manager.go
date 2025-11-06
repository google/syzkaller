// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package kfuzztestmanager

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kfuzztest"
	executor "github.com/google/syzkaller/pkg/kfuzztest-executor"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type kFuzzTestManager struct {
	fuzzer atomic.Pointer[fuzzer.Fuzzer]
	source queue.Source
	target *prog.Target
	config Config
}

type Config struct {
	VmlinuxPath     string
	Cooldown        uint32
	DisplayInterval uint32
	NumThreads      int
	EnabledTargets  []string
}

func NewKFuzzTestManager(ctx context.Context, cfg Config) (*kFuzzTestManager, error) {
	var mgr kFuzzTestManager

	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "extracting KFuzzTest targets from \"%s\" (this will take a few seconds)", cfg.VmlinuxPath)
	calls, err := kfuzztest.ActivateKFuzzTargets(target, cfg.VmlinuxPath)
	if err != nil {
		return nil, err
	}

	enabledCalls := make(map[*prog.Syscall]bool)
	for _, call := range calls {
		enabledCalls[call] = true
	}

	// Disable all calls that weren't explicitly enabled.
	if len(cfg.EnabledTargets) > 0 {
		enabledMap := make(map[string]bool)
		for _, enabled := range cfg.EnabledTargets {
			enabledMap[enabled] = true
		}
		for syscall := range enabledCalls {
			testName, isSyzKFuzzTest := kfuzztest.GetTestName(syscall)
			_, isEnabled := enabledMap[testName]
			if isSyzKFuzzTest && syscall.Attrs.KFuzzTest && isEnabled {
				enabledMap[testName] = true
			} else {
				delete(enabledCalls, syscall)
			}
		}
	}

	dispDiscoveredTargets := func() string {
		var builder strings.Builder
		totalEnabled := 0

		builder.WriteString("enabled KFuzzTest targets: [\n")
		for targ, enabled := range enabledCalls {
			if enabled {
				fmt.Fprintf(&builder, "\t%s,\n", targ.Name)
				totalEnabled++
			}
		}
		fmt.Fprintf(&builder, "]\ntotal = %d\n", totalEnabled)
		return builder.String()
	}
	log.Logf(0, "%s", dispDiscoveredTargets())

	corpus := corpus.NewCorpus(ctx)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	fuzzerObj := fuzzer.NewFuzzer(ctx, &fuzzer.Config{
		Corpus:         corpus,
		Snapshot:       false,
		Coverage:       true,
		FaultInjection: false,
		Comparisons:    false,
		Collide:        false,
		EnabledCalls:   enabledCalls,
		NoMutateCalls:  make(map[int]bool),
		FetchRawCover:  false,
		Logf: func(level int, msg string, args ...any) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
		NewInputFilter: func(call string) bool {
			// Don't filter anything.
			return true
		},
	}, rnd, target)

	// TODO: Sufficient for startup, but not ideal that we are passing a
	// manager config here. Would require changes to pkg/fuzzer if we wanted to
	// avoid the dependency.
	execOpts := fuzzer.DefaultExecOpts(&mgrconfig.Config{Sandbox: "none"}, 0, false)

	mgr.target = target
	mgr.fuzzer.Store(fuzzerObj)
	mgr.source = queue.DefaultOpts(fuzzerObj, execOpts)
	mgr.config = cfg

	return &mgr, nil
}

func (mgr *kFuzzTestManager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	// Launches the executor threads.
	executor := executor.NewKFuzzTestExecutor(ctx, mgr.config.NumThreads, mgr.config.Cooldown)

	// Display logs periodically.
	display := func() {
		defer wg.Done()
		mgr.displayLoop(ctx)
	}

	wg.Add(1)
	go display()

FuzzLoop:
	for {
		select {
		case <-ctx.Done():
			break FuzzLoop
		default:
		}

		req := mgr.source.Next()
		if req == nil {
			continue
		}

		executor.Submit(req)
	}

	log.Log(0, "fuzzing finished, shutting down executor")
	executor.Shutdown()
	wg.Wait()

	const filepath string = "pcs.out"
	log.Logf(0, "writing PCs out to \"%s\"", filepath)
	if err := mgr.writePCs(filepath); err != nil {
		log.Logf(0, "failed to write PCs: %v", err)
	}

	log.Log(0, "KFuzzTest manager exited")
}

func (mgr *kFuzzTestManager) writePCs(filepath string) error {
	pcs := mgr.fuzzer.Load().Config.Corpus.Cover()
	slices.Sort(pcs)
	var builder strings.Builder
	for _, pc := range pcs {
		fmt.Fprintf(&builder, "0x%x\n", pc)
	}
	return os.WriteFile(filepath, []byte(builder.String()), 0644)
}

func (mgr *kFuzzTestManager) displayLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(mgr.config.DisplayInterval) * time.Second)
	defer ticker.Stop()
	for {
		var buf strings.Builder
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, stat := range stat.Collect(stat.Console) {
				fmt.Fprintf(&buf, "%v=%v ", stat.Name, stat.Value)
			}
			log.Log(0, buf.String())
		}
	}
}
