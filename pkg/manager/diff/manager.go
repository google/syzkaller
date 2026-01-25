// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/vm"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Debug        bool
	PatchedOnly  chan *Bug
	BaseCrashes  chan string
	Store        *manager.DiffFuzzerStore
	ArtifactsDir string // Where to store the artifacts that supplement the logs.
	// The fuzzer waits no more than MaxTriageTime time until it starts taking VMs away
	// for bug reproduction.
	// The option may help find a balance between spending too much time triaging
	// the corpus and not reaching a proper kernel coverage.
	MaxTriageTime time.Duration
	// If non-empty, the fuzzer will spend no more than this amount of time
	// trying to reach the modified code. The time is counted since the moment
	// 99% of the corpus is triaged.
	FuzzToReachPatched time.Duration
	// The callback may be used to consult external systems on whether
	// the crash should be ignored. E.g. because it doesn't match the filter or
	// the particular base kernel has already been seen to crash with the given title.
	// It helps reduce the number of unnecessary reproductions.
	IgnoreCrash func(context.Context, string) (bool, error)

	runner   runner
	runRepro func(context.Context, []byte, repro.Environment) (*repro.Result, *repro.Stats, error)
}

func (cfg *Config) TriageDeadline() <-chan time.Time {
	if cfg.MaxTriageTime == 0 {
		return nil
	}
	return time.After(cfg.MaxTriageTime)
}

type Bug struct {
	// The report from the patched kernel.
	Report *report.Report
	Repro  *repro.Result
}

func Run(ctx context.Context, baseCfg, newCfg *mgrconfig.Config, cfg Config) error {
	if cfg.PatchedOnly == nil {
		return fmt.Errorf("you must set up a patched only channel")
	}
	base, err := setup("base", baseCfg, cfg.Debug)
	if err != nil {
		return err
	}
	new, err := setup("new", newCfg, cfg.Debug)
	if err != nil {
		return err
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		info, err := manager.LoadSeeds(newCfg, true)
		if err != nil {
			return err
		}
		select {
		case new.candidates <- info.Candidates:
		case <-ctx.Done():
		}
		return nil
	})

	stream := queue.NewRandomQueue(4096, rand.New(rand.NewSource(time.Now().UnixNano())))
	base.source = stream
	new.duplicateInto = stream

	if cfg.runRepro == nil {
		cfg.runRepro = repro.Run
	}
	if cfg.runner == nil {
		cfg.runner = &reproRunner{done: make(chan reproRunnerResult, 2)}
	}

	diffCtx := &diffContext{
		cfg:           cfg,
		doneRepro:     make(chan *manager.ReproResult),
		base:          base,
		new:           new,
		store:         cfg.Store,
		reproAttempts: map[string]int{},
		patchedOnly:   cfg.PatchedOnly,
	}
	if newCfg.HTTP != "" {
		diffCtx.http = &manager.HTTPServer{
			Cfg:       newCfg,
			StartTime: time.Now(),
			DiffStore: cfg.Store,
			Pools: map[string]*vm.Dispatcher{
				new.name:  new.pool,
				base.name: base.pool,
			},
		}
		new.http = diffCtx.http
	}
	eg.Go(func() error {
		return diffCtx.Loop(ctx)
	})
	return eg.Wait()
}

type Kernel interface {
	Loop(ctx context.Context) error
	Crashes() <-chan *report.Report
	TriageProgress() float64
	ProgsPerArea() map[string]int
	CoverFilters() manager.CoverageFilters
	Config() *mgrconfig.Config
	Pool() *vm.Dispatcher
	Features() flatrpc.Feature
	Reporter() *report.Reporter
}

type diffContext struct {
	cfg   Config
	store *manager.DiffFuzzerStore
	http  *manager.HTTPServer

	doneRepro   chan *manager.ReproResult
	base        Kernel
	new         Kernel
	patchedOnly chan *Bug

	mu            sync.Mutex
	reproAttempts map[string]int
}

const (
	// Don't start reproductions until 90% of the corpus has been triaged.
	corpusTriageToRepro = 0.9
	// Start to monitor whether we reached the modified files only after triaging 99%.
	corpusTriageToMonitor = 0.99
)

func (dc *diffContext) Loop(ctx context.Context) error {
	g, groupCtx := errgroup.WithContext(ctx)
	reproLoop := manager.NewReproLoop(dc, dc.new.Pool().Total()-dc.new.Config().FuzzingVMs, false)
	if dc.http != nil {
		dc.http.ReproLoop = reproLoop
		g.Go(func() error {
			return dc.http.Serve(groupCtx)
		})
	}

	g.Go(func() error {
		select {
		case <-groupCtx.Done():
			return nil
		case <-dc.waitCorpusTriage(groupCtx, corpusTriageToRepro):
		case <-dc.cfg.TriageDeadline():
			log.Logf(0, "timed out waiting for coprus triage")
		}
		log.Logf(0, "starting bug reproductions")
		reproLoop.Loop(groupCtx)
		return nil
	})

	g.Go(func() error { return dc.monitorPatchedCoverage(groupCtx) })
	g.Go(func() error { return dc.base.Loop(groupCtx) })
	g.Go(func() error { return dc.new.Loop(groupCtx) })

	runner := dc.cfg.runner
	statTimer := time.NewTicker(5 * time.Minute)
loop:
	for {
		select {
		case <-groupCtx.Done():
			break loop
		case <-statTimer.C:
			vals := make(map[string]int)
			for _, stat := range stat.Collect(stat.All) {
				vals[stat.Name] = stat.V
			}
			data, _ := json.MarshalIndent(vals, "", "  ")
			log.Logf(0, "STAT %s", data)
		case rep := <-dc.base.Crashes():
			log.Logf(1, "base crash: %v", rep.Title)
			dc.reportBaseCrash(groupCtx, rep)
		case ret := <-runner.Results():
			dc.handleReproResult(groupCtx, ret, reproLoop)
		case ret := <-dc.doneRepro:
			// We have finished reproducing a crash from the patched instance.
			if ret.Repro != nil && ret.Repro.Report != nil {
				origTitle := ret.Crash.Report.Title
				if ret.Repro.Report.Title == origTitle {
					origTitle = "-SAME-"
				}
				log.Logf(1, "found repro for %q (orig title: %q, reliability: %2.f), took %.2f minutes",
					ret.Repro.Report.Title, origTitle, ret.Repro.Reliability, ret.Stats.TotalTime.Minutes())

				dc.store.UpdateStatus(ret.Repro.Report.Title, manager.DiffBugStatusVerifying)

				g.Go(func() error {
					runner.Run(groupCtx, dc.base, ret.Repro, ret.Crash.FullRepro)
					return nil
				})
			} else {
				origTitle := ret.Crash.Report.Title
				log.Logf(1, "failed repro for %q, err=%s", origTitle, ret.Err)
				dc.store.UpdateStatus(origTitle, manager.DiffBugStatusCompleted)
			}
			dc.store.SaveRepro(ret)
		case rep := <-dc.new.Crashes():
			// A new crash is found on the patched instance.
			crash := &manager.Crash{Report: rep}
			need := dc.NeedRepro(crash)
			log.Logf(0, "patched crashed: %v [need repro = %v]",
				rep.Title, need)
			dc.store.PatchedCrashed(rep.Title, rep.Report, rep.Output)
			if need {
				dc.store.UpdateStatus(rep.Title, manager.DiffBugStatusVerifying)
				reproLoop.Enqueue(crash)
			} else {
				dc.store.UpdateStatus(rep.Title, manager.DiffBugStatusIgnored)
			}
		}
	}
	return g.Wait()
}

func (dc *diffContext) handleReproResult(ctx context.Context, ret reproRunnerResult, reproLoop *manager.ReproLoop) {
	// We have run the reproducer on the base instance.

	// A sanity check: the base kernel might have crashed with the same title
	// since the moment we have stared the reproduction / running on the repro base.
	ignored := dc.ignoreCrash(ctx, ret.reproReport.Title)
	if ret.crashReport == nil && ignored {
		// Report it as error so that we could at least find it in the logs.
		log.Errorf("resulting crash of an approved repro result is to be ignored: %s",
			ret.reproReport.Title)
	} else if ret.crashReport == nil {
		dc.store.BaseNotCrashed(ret.reproReport.Title)
		select {
		case <-ctx.Done():
		case dc.patchedOnly <- &Bug{
			Report: ret.reproReport,
			Repro:  ret.repro,
		}:
		}
		// Now that we know this bug only affects the patch kernel, we can spend more time
		// generating a minimalistic repro and a C repro.
		log.Logf(0, "patched-only: %s", ret.reproReport.Title)
		if !ret.fullRepro {
			reproLoop.Enqueue(&manager.Crash{
				Report: &report.Report{
					Title:  ret.reproReport.Title,
					Output: ret.repro.Prog.Serialize(),
				},
				FullRepro: true,
			})
		}
	} else {
		dc.reportBaseCrash(ctx, ret.crashReport)
		log.Logf(0, "crashes both: %s / %s", ret.reproReport.Title, ret.crashReport.Title)
	}
}

func (dc *diffContext) ignoreCrash(ctx context.Context, title string) bool {
	if dc.store.EverCrashedBase(title) {
		return true
	}
	// Let's try to ask the external systems about it as well.
	if dc.cfg.IgnoreCrash != nil {
		ignore, err := dc.cfg.IgnoreCrash(ctx, title)
		if err != nil {
			log.Logf(0, "a call to IgnoreCrash failed: %v", err)
		} else {
			if ignore {
				log.Logf(0, "base crash %q is to be ignored", title)
			}
			return ignore
		}
	}
	return false
}

func (dc *diffContext) reportBaseCrash(ctx context.Context, rep *report.Report) {
	dc.store.BaseCrashed(rep.Title, rep.Report)
	if dc.cfg.BaseCrashes == nil {
		return
	}
	select {
	case dc.cfg.BaseCrashes <- rep.Title:
	case <-ctx.Done():
	}
}

func (dc *diffContext) waitCorpusTriage(ctx context.Context, threshold float64) chan struct{} {
	const triageCheckPeriod = 30 * time.Second
	ret := make(chan struct{})
	go func() {
		for {
			triaged := dc.new.TriageProgress()
			if triaged >= threshold {
				log.Logf(0, "triaged %.1f%% of the corpus", triaged*100.0)
				close(ret)
				return
			}
			select {
			case <-time.After(triageCheckPeriod):
			case <-ctx.Done():
				return
			}
		}
	}()
	return ret
}

var ErrPatchedAreaNotReached = errors.New("fuzzer has not reached the patched area")

func (dc *diffContext) monitorPatchedCoverage(ctx context.Context) error {
	if dc.cfg.FuzzToReachPatched == 0 {
		// The feature is disabled.
		return nil
	}

	// First wait until we have almost triaged all of the corpus.
	select {
	case <-ctx.Done():
		return nil
	case <-dc.waitCorpusTriage(ctx, corpusTriageToMonitor):
	}

	// By this moment, we must have coverage filters already filled out.
	focusPCs := 0
	// The last one is "everything else", so it's not of interest.
	coverFilters := dc.new.CoverFilters()
	for i := 0; i < len(coverFilters.Areas)-1; i++ {
		focusPCs += len(coverFilters.Areas[i].CoverPCs)
	}
	if focusPCs == 0 {
		// No areas were configured.
		log.Logf(1, "no PCs in the areas of focused fuzzing, skipping the zero patched coverage check")
		return nil
	}

	// Then give the fuzzer some change to get through.
	select {
	case <-time.After(dc.cfg.FuzzToReachPatched):
	case <-ctx.Done():
		return nil
	}
	focusAreaStats := dc.new.ProgsPerArea()
	if focusAreaStats[symbolsArea]+focusAreaStats[filesArea]+focusAreaStats[includesArea] > 0 {
		log.Logf(0, "fuzzer has reached the modified code (%d + %d + %d), continuing fuzzing",
			focusAreaStats[symbolsArea], focusAreaStats[filesArea], focusAreaStats[includesArea])
		return nil
	}
	log.Logf(0, "fuzzer has not reached the modified code in %s, aborting",
		dc.cfg.FuzzToReachPatched)
	return ErrPatchedAreaNotReached
}

// TODO: instead of this limit, consider expotentially growing delays between reproduction attempts.
const maxReproAttempts = 6

func needReproForTitle(title string) bool {
	if strings.Contains(title, "no output") ||
		strings.Contains(title, "lost connection") ||
		strings.Contains(title, "detected stall") ||
		strings.Contains(title, "SYZ") {
		// Don't waste time reproducing these.
		return false
	}
	return true
}

func (dc *diffContext) NeedRepro(crash *manager.Crash) bool {
	if crash.FullRepro {
		return true
	}
	if !needReproForTitle(crash.Title) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if dc.ignoreCrash(ctx, crash.Title) {
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.reproAttempts[crash.Title] <= maxReproAttempts
}

func (dc *diffContext) RunRepro(ctx context.Context, crash *manager.Crash) *manager.ReproResult {
	dc.mu.Lock()
	dc.reproAttempts[crash.Title]++
	dc.mu.Unlock()

	res, stats, err := dc.cfg.runRepro(ctx, crash.Output, repro.Environment{
		Config:   dc.new.Config(),
		Features: dc.new.Features(),
		Reporter: dc.new.Reporter(),
		Pool:     dc.new.Pool(),
		Fast:     !crash.FullRepro,
	})
	if res != nil && res.Report != nil {
		dc.mu.Lock()
		dc.reproAttempts[res.Report.Title] = maxReproAttempts
		dc.mu.Unlock()
	}
	ret := &manager.ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}

	select {
	case dc.doneRepro <- ret:
	case <-ctx.Done():
		// If the context is cancelled, no one may be listening on doneRepro.
	}
	return ret
}

func (dc *diffContext) ResizeReproPool(size int) {
	dc.new.Pool().ReserveForRun(size)
}
