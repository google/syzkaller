// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

type DiffFuzzerConfig struct {
	Debug       bool
	PatchedOnly chan *UniqueBug
}

type UniqueBug struct {
	// The report from the patched kernel.
	Report *report.Report
	Repro  *repro.Result
}

func RunDiffFuzzer(ctx context.Context, baseCfg, newCfg *mgrconfig.Config, cfg DiffFuzzerConfig) error {
	base, err := setup(ctx, "base", baseCfg, cfg.Debug)
	if err != nil {
		return err
	}
	new, err := setup(ctx, "new", newCfg, cfg.Debug)
	if err != nil {
		return err
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		info, err := LoadSeeds(newCfg, true)
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

	store := &DiffFuzzerStore{BasePath: new.cfg.Workdir}
	diffCtx := &diffContext{
		doneRepro:     make(chan *ReproResult),
		base:          base,
		new:           new,
		store:         store,
		reproAttempts: map[string]int{},
		patchedOnly:   cfg.PatchedOnly,
	}
	if newCfg.HTTP != "" {
		diffCtx.http = &HTTPServer{
			Cfg:       newCfg,
			StartTime: time.Now(),
			DiffStore: store,
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

type diffContext struct {
	store *DiffFuzzerStore
	http  *HTTPServer

	doneRepro   chan *ReproResult
	base        *kernelContext
	new         *kernelContext
	patchedOnly chan *UniqueBug

	mu            sync.Mutex
	reproAttempts map[string]int
}

func (dc *diffContext) Loop(baseCtx context.Context) error {
	g, ctx := errgroup.WithContext(baseCtx)
	reproLoop := NewReproLoop(dc, dc.new.pool.Total()-dc.new.cfg.FuzzingVMs, false)
	if dc.http != nil {
		dc.http.ReproLoop = reproLoop
		g.Go(func() error {
			return dc.http.Serve(ctx)
		})
	}
	g.Go(func() error {
		// Let both base and patched instances somewhat progress in fuzzing before we take
		// VMs away for bug reproduction.
		// TODO: determine the exact moment of corpus triage.
		select {
		case <-time.After(15 * time.Minute):
		case <-ctx.Done():
			return nil
		}
		log.Logf(0, "starting bug reproductions")
		reproLoop.Loop(ctx)
		return nil
	})

	g.Go(dc.base.Loop)
	g.Go(dc.new.Loop)

	runner := &reproRunner{done: make(chan reproRunnerResult, 2), kernel: dc.base}
	rareStat := time.NewTicker(5 * time.Minute)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-rareStat.C:
			vals := make(map[string]int)
			for _, stat := range stat.Collect(stat.All) {
				vals[stat.Name] = stat.V
			}
			data, _ := json.MarshalIndent(vals, "", "  ")
			log.Logf(0, "STAT %s", data)
		case rep := <-dc.base.crashes:
			log.Logf(1, "base crash: %v", rep.Title)
			dc.store.BaseCrashed(rep.Title, rep.Report)
		case ret := <-runner.done:
			if ret.crashReport == nil {
				dc.store.BaseNotCrashed(ret.origReport.Title)
				if dc.patchedOnly != nil {
					dc.patchedOnly <- &UniqueBug{
						Report: ret.origReport,
						Repro:  ret.repro,
					}
				}
				log.Logf(0, "patched-only: %s", ret.origReport.Title)
			} else {
				dc.store.BaseCrashed(ret.origReport.Title, ret.origReport.Report)
				log.Logf(0, "crashes both: %s / %s", ret.origReport.Title, ret.crashReport.Title)
			}
		case ret := <-dc.doneRepro:
			if ret.Repro != nil && ret.Repro.Report != nil {
				origTitle := ret.Crash.Report.Title
				if ret.Repro.Report.Title == origTitle {
					origTitle = "-SAME-"
				}
				log.Logf(1, "found repro for %q (orig title: %q), took %.2f minutes",
					ret.Repro.Report.Title, origTitle, ret.Stats.TotalTime.Minutes())
				g.Go(func() error {
					runner.Run(ctx, ret.Repro)
					return nil
				})
			} else {
				origTitle := ret.Crash.Report.Title
				log.Logf(1, "failed repro for %q, err=%s", origTitle, ret.Err)
			}
			dc.store.SaveRepro(ret)
		case rep := <-dc.new.crashes:
			crash := &Crash{Report: rep}
			need := dc.NeedRepro(crash)
			log.Logf(0, "patched crashed: %v [need repro = %v]",
				rep.Title, need)
			dc.store.PatchedCrashed(rep.Title, rep.Report, rep.Output)
			if need {
				reproLoop.Enqueue(crash)
			}
		}
	}
	return g.Wait()
}

// TODO: instead of this limit, consider expotentially growing delays between reproduction attempts.
const maxReproAttempts = 6

func (dc *diffContext) NeedRepro(crash *Crash) bool {
	if strings.Contains(crash.Title, "no output") ||
		strings.Contains(crash.Title, "lost connection") ||
		strings.Contains(crash.Title, "stall") ||
		strings.Contains(crash.Title, "SYZ") {
		// Don't waste time reproducing these.
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.store.EverCrashedBase(crash.Title) {
		return false
	}
	if dc.reproAttempts[crash.Title] > maxReproAttempts {
		return false
	}
	return true
}

func (dc *diffContext) RunRepro(crash *Crash) *ReproResult {
	dc.mu.Lock()
	dc.reproAttempts[crash.Title]++
	dc.mu.Unlock()

	res, stats, err := repro.Run(context.Background(), crash.Output, repro.Environment{
		Config:   dc.new.cfg,
		Features: dc.new.features,
		Reporter: dc.new.reporter,
		Pool:     dc.new.pool,
		Fast:     true,
	})
	if res != nil && res.Report != nil {
		dc.mu.Lock()
		dc.reproAttempts[res.Report.Title] = maxReproAttempts
		dc.mu.Unlock()
	}
	ret := &ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}
	dc.doneRepro <- ret
	return ret
}

func (dc *diffContext) ResizeReproPool(size int) {
	dc.new.pool.ReserveForRun(size)
}

type kernelContext struct {
	name       string
	ctx        context.Context
	debug      bool
	cfg        *mgrconfig.Config
	reporter   *report.Reporter
	fuzzer     atomic.Pointer[fuzzer.Fuzzer]
	serv       rpcserver.Server
	servStats  rpcserver.Stats
	crashes    chan *report.Report
	pool       *vm.Dispatcher
	features   flatrpc.Feature
	candidates chan []fuzzer.Candidate

	coverFilters    CoverageFilters
	reportGenerator *ReportGeneratorWrapper

	http          *HTTPServer
	source        queue.Source
	duplicateInto queue.Executor
}

func setup(ctx context.Context, name string, cfg *mgrconfig.Config, debug bool) (*kernelContext, error) {
	osutil.MkdirAll(cfg.Workdir)

	kernelCtx := &kernelContext{
		name:            name,
		debug:           debug,
		ctx:             ctx,
		cfg:             cfg,
		crashes:         make(chan *report.Report, 128),
		candidates:      make(chan []fuzzer.Candidate),
		servStats:       rpcserver.NewNamedStats(name),
		reportGenerator: ReportGeneratorCache(cfg),
	}

	var err error
	kernelCtx.reporter, err = report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter for %q: %w", name, err)
	}

	kernelCtx.serv, err = rpcserver.New(&rpcserver.RemoteConfig{
		Config:  cfg,
		Manager: kernelCtx,
		Stats:   kernelCtx.servStats,
		Debug:   debug,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc server for %q: %w", name, err)
	}

	vmPool, err := vm.Create(cfg, debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm.Pool for %q: %w", name, err)
	}

	kernelCtx.pool = vm.NewDispatcher(vmPool, kernelCtx.fuzzerInstance)
	return kernelCtx, nil
}

func (kc *kernelContext) Loop() error {
	if err := kc.serv.Listen(); err != nil {
		return fmt.Errorf("failed to start rpc server: %w", err)
	}
	eg, ctx := errgroup.WithContext(kc.ctx)
	eg.Go(func() error {
		return kc.serv.Serve(ctx)
	})
	eg.Go(func() error {
		kc.pool.Loop(ctx)
		return nil
	})
	return eg.Wait()
}

func (kc *kernelContext) MaxSignal() signal.Signal {
	if fuzzer := kc.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (kc *kernelContext) BugFrames() (leaks, races []string) {
	return nil, nil
}

func (kc *kernelContext) MachineChecked(features flatrpc.Feature,
	syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	log.Logf(0, "%s: machine check complete", kc.name)
	kc.features = features

	var source queue.Source
	if kc.source == nil {
		source = queue.Tee(kc.setupFuzzer(features, syscalls), kc.duplicateInto)
	} else {
		source = kc.source
	}
	opts := fuzzer.DefaultExecOpts(kc.cfg, features, kc.debug)
	return queue.DefaultOpts(source, opts), nil
}

func (kc *kernelContext) setupFuzzer(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	corpusObj := corpus.NewFocusedCorpus(kc.ctx, nil, kc.coverFilters.Areas)
	fuzzerObj := fuzzer.NewFuzzer(kc.ctx, &fuzzer.Config{
		Corpus:   corpusObj,
		Coverage: kc.cfg.Cover,
		// TODO: it may be unstable between different revisions though.
		// For now it's only kept true because it seems to increase repro chances in local runs (???).
		FaultInjection: true,
		Comparisons:    features&flatrpc.FeatureComparisons != 0,
		Collide:        true,
		EnabledCalls:   syscalls,
		NoMutateCalls:  kc.cfg.NoMutateCalls,
		PatchTest:      true,
		Logf: func(level int, msg string, args ...interface{}) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
	}, rnd, kc.cfg.Target)
	kc.fuzzer.Store(fuzzerObj)

	if kc.http != nil {
		kc.http.Fuzzer.Store(fuzzerObj)
		kc.http.EnabledSyscalls.Store(syscalls)
		kc.http.Corpus.Store(corpusObj)
	}

	var candidates []fuzzer.Candidate
	select {
	case candidates = <-kc.candidates:
	case <-kc.ctx.Done():
		// The loop will be aborted later.
		break
	}

	filtered := FilterCandidates(candidates, syscalls, false).Candidates
	log.Logf(0, "%s: adding %d seeds", kc.name, len(filtered))
	fuzzerObj.AddCandidates(filtered)

	go func() {
		if !kc.cfg.Cover {
			return
		}
		for {
			select {
			case <-time.After(time.Second):
			case <-kc.ctx.Done():
				return
			}
			newSignal := fuzzerObj.Cover.GrabSignalDelta()
			if len(newSignal) == 0 {
				continue
			}
			kc.serv.DistributeSignalDelta(newSignal)
		}
	}()
	return fuzzerObj
}

func (kc *kernelContext) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	kc.reportGenerator.Init(modules)
	filters, err := PrepareCoverageFilters(kc.reportGenerator, kc.cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	kc.coverFilters = filters
	log.Logf(0, "cover filter size: %d", len(filters.ExecutorFilter))
	if kc.http != nil {
		kc.http.Cover.Store(&CoverageInfo{
			Modules:         modules,
			ReportGenerator: kc.reportGenerator,
			CoverFilter:     filters.ExecutorFilter,
		})
	}
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func (kc *kernelContext) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	index := inst.Index()
	injectExec := make(chan bool, 10)
	kc.serv.CreateInstance(index, injectExec, updInfo)
	rep, err := kc.runInstance(ctx, inst, injectExec)
	lastExec, _ := kc.serv.ShutdownInstance(index, rep != nil)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		kc.crashes <- rep
	}
	if err != nil {
		log.Errorf("#%d run failed: %s", inst.Index(), err)
	}
}

func (kc *kernelContext) runInstance(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) (*report.Report, error) {
	fwdAddr, err := inst.Forward(kc.serv.Port())
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}
	executorBin, err := inst.Copy(kc.cfg.ExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %w", err)
	}
	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manager's address")
	}
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	_, rep, err := inst.Run(kc.cfg.Timeouts.VMRunningTime, kc.reporter, cmd,
		vm.ExitTimeout, vm.StopContext(ctx), vm.InjectExecuting(injectExec),
		vm.EarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			kc.serv.StopFuzzing(inst.Index())
		}),
	)
	return rep, err
}

// reproRunner is used to run reproducers on the base kernel to determine whether it is affected.
type reproRunner struct {
	done    chan reproRunnerResult
	running atomic.Int64
	kernel  *kernelContext
}

type reproRunnerResult struct {
	origReport  *report.Report
	crashReport *report.Report
	repro       *repro.Result
}

func (rr *reproRunner) Run(ctx context.Context, r *repro.Result) {
	pool := rr.kernel.pool
	cnt := int(rr.running.Add(1))
	pool.ReserveForRun(min(cnt, pool.Total()))
	defer func() {
		cnt := int(rr.running.Add(-1))
		rr.kernel.pool.ReserveForRun(min(cnt, pool.Total()))
	}()

	ret := reproRunnerResult{origReport: r.Report, repro: r}

	var result *instance.RunResult
	var err error
	for i := 0; i < 3; i++ {
		opts := r.Opts
		opts.Repeat = true
		if i == 0 || i == 1 {
			// Two times out of 3, test with Threaded=true.
			// The third time we leave it as is in case it was important.
			opts.Threaded = true
		}
		pool.Run(func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
			var ret *instance.ExecProgInstance
			ret, err = instance.SetupExecProg(inst, rr.kernel.cfg, rr.kernel.reporter, nil)
			if err != nil {
				return
			}
			result, err = ret.RunSyzProg(instance.ExecParams{
				SyzProg:  r.Prog.Serialize(),
				Duration: max(r.Duration, time.Minute),
				Opts:     opts,
			})
		})
		crashed := result != nil && result.Report != nil
		log.Logf(1, "attempt #%d to run %q on base: crashed=%v", i, ret.origReport.Title, crashed)
		if crashed {
			ret.crashReport = result.Report
			break
		}
	}
	if err != nil {
		log.Errorf("failed to run repro: %v", err)
		return
	}
	select {
	case rr.done <- ret:
	case <-ctx.Done():
	}
}

func PatchFocusAreas(cfg *mgrconfig.Config, gitPatches [][]byte) {
	direct, transitive := affectedFiles(cfg, gitPatches)
	if len(direct) > 0 {
		sort.Strings(direct)
		log.Logf(0, "adding directly modified files to focus_order: %q", direct)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: "modified",
				Filter: mgrconfig.CovFilterCfg{
					Files: direct,
				},
				Weight: 3.0,
			})
	}

	if len(transitive) > 0 {
		sort.Strings(transitive)
		log.Logf(0, "adding transitively affected to focus_order: %q", transitive)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: "included",
				Filter: mgrconfig.CovFilterCfg{
					Files: transitive,
				},
				Weight: 2.0,
			})
	}

	// Still fuzz the rest of the kernel.
	if len(cfg.Experimental.FocusAreas) > 0 {
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Weight: 1.0,
			})
	}
}

func affectedFiles(cfg *mgrconfig.Config, gitPatches [][]byte) (direct, transitive []string) {
	const maxAffectedByHeader = 50

	directMap := make(map[string]struct{})
	transitiveMap := make(map[string]struct{})
	var allFiles []string
	for _, patch := range gitPatches {
		allFiles = append(allFiles, vcs.ParseGitDiff(patch)...)
	}
	for _, file := range allFiles {
		directMap[file] = struct{}{}
		if strings.HasSuffix(file, ".h") && cfg.KernelSrc != "" {
			// Ideally, we should combine this with the recompilation process - then we know
			// exactly which files were affected by the patch.
			out, err := osutil.RunCmd(time.Minute, cfg.KernelSrc, "/usr/bin/grep",
				"-rl", "--include", `*.c`, `<`+strings.TrimPrefix(file, "include/")+`>`)
			if err != nil {
				log.Logf(0, "failed to grep for the header usages: %v", err)
				continue
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) >= maxAffectedByHeader {
				// It's too widespread. It won't help us focus on anything.
				log.Logf(0, "the header %q is included in too many files (%d)", file, len(lines))
				continue
			}
			for _, name := range lines {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				transitiveMap[name] = struct{}{}
			}
		}
	}
	for name := range directMap {
		direct = append(direct, name)
	}
	for name := range transitiveMap {
		if _, ok := directMap[name]; ok {
			continue
		}
		transitive = append(transitive, name)
	}
	return
}
