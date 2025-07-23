package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type kFuzzTestManager struct {
	ctx    context.Context
	fuzzer *fuzzer.Fuzzer
	source queue.Source
	target *prog.Target
	stats  *stats
	config config
}

type config struct {
	vmlinuxPath         string
	timeoutMilliseconds uint32
	displayInterval     uint32
	numThreads          int
	enabledTargets      []string
}

func newKFuzzTestManager(ctx context.Context, cfg config) (*kFuzzTestManager, error) {
	var mgr kFuzzTestManager

	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "extracting KFuzzTest targets from \"%s\" (this will take a few seconds)", *flagVmlinux)
	enabledCalls := make(map[*prog.Syscall]bool)
	err = kfuzztest.ActivateKFuzzTargets(cfg.vmlinuxPath, target, &enabledCalls)
	if err != nil {
		return nil, err
	}

	// Disable all calls that weren't explicitly enabled.
	if len(cfg.enabledTargets) > 0 {
		enabledMap := make(map[string]bool)
		for _, enabled := range cfg.enabledTargets {
			enabledMap[enabled] = true
		}
		for syscall := range enabledCalls {
			if testName, isKFuzzTest := kfuzztest.GetTestName(syscall); isKFuzzTest {
				if _, contains := enabledMap[testName]; !contains {
					delete(enabledCalls, syscall)
				}
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
	emptyNoMutateCalls := make(map[int]bool)
	fuzzerObj := fuzzer.NewFuzzer(ctx, &fuzzer.Config{
		Corpus:         corpus,
		Snapshot:       false,
		Coverage:       true,
		FaultInjection: false,
		Comparisons:    false,
		Collide:        false,
		EnabledCalls:   enabledCalls,
		NoMutateCalls:  emptyNoMutateCalls,
		FetchRawCover:  false,
		Logf: func(level int, msg string, args ...any) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
		NewInputFilter: func(call string) bool {
			// Returning false on everything should suffice for now.
			return false
		},
	}, rnd, target)

	// TODO: Sufficient for startup, but not ideal that we are passing a
	// manager config here. Cleaning this up may require pkg/fuzzer.
	execOpts := fuzzer.DefaultExecOpts(&mgrconfig.Config{Sandbox: "none"}, 0, false)

	mgr.ctx = ctx
	mgr.target = target
	mgr.fuzzer = fuzzerObj
	mgr.source = queue.DefaultOpts(fuzzerObj, execOpts)
	mgr.config = cfg
	mgr.stats = newStats(cfg.enabledTargets)

	return &mgr, nil
}

func (mgr *kFuzzTestManager) Run() {
	var wg sync.WaitGroup

	statChan := make(chan kfuzztest.ExecResult, 1024)
	// Launches the executor threads.
	executor := kfuzztest.NewKFuzzTestExecutor(mgr.ctx, mgr.config.numThreads, statChan)

	// Display logs periodically.
	display := func() {
		defer wg.Done()
		mgr.displayLoop()
	}
	// Collect stats.
	collectStats := func() {
		defer wg.Done()
		for res := range statChan {
			err := mgr.stats.Report(res)
			if err != nil {
				log.Logf(1, "%v", err)
			}
		}
	}

	wg.Add(2)
	go collectStats()
	go display()

FuzzLoop:
	for {
		select {
		case <-mgr.ctx.Done():
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
	close(statChan)
	wg.Wait()

	log.Log(0, "writing PCs out to \"./pc.out\"")
	if err := mgr.writePCs("pcs.out"); err != nil {
		log.Logf(0, "failed to write PCs")
	}

	log.Log(0, "KFuzzTest manager exited")
}

func (mgr *kFuzzTestManager) writePCs(filepath string) error {
	sigs := mgr.fuzzer.Cover.CopyMaxSignal()
	pcs := []uint64{}
	for sig := range sigs {
		pcs = append(pcs, uint64(sig))
	}
	slices.Sort(pcs)
	var builder strings.Builder
	for _, pc := range pcs {
		fmt.Fprintf(&builder, "%x\n", pc)
	}
	return os.WriteFile(filepath, []byte(builder.String()), 0644)
}

func (mgr *kFuzzTestManager) displayLoop() {
	ticker := time.NewTicker(time.Duration(mgr.config.displayInterval) * time.Second)
	defer ticker.Stop()

	prevTotal := uint64(0)
	for {
		select {
		case <-mgr.ctx.Done():
			return
		case <-ticker.C:
			currTotal, failures := mgr.stats.Poll()
			callsPerSec := (currTotal - prevTotal) / uint64(mgr.config.displayInterval)
			prevTotal = currTotal

			coverage := len(mgr.fuzzer.Cover.CopyMaxSignal())
			log.Logf(0, "%d execs (%d/sec), %d failures, covered PCs = %d", currTotal, callsPerSec, failures, coverage)
		}
	}
}
