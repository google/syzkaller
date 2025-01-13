// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
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
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

var (
	flagBaseConfig = flag.String("base", "", "base config")
	flagNewConfig  = flag.String("new", "", "new config (treated as the main one)")
	flagDebug      = flag.Bool("debug", false, "dump all VM output to console")
	flagPatch      = flag.String("patch", "", "a git patch")
)

func main() {
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad syz-diff build: build with make, run bin/syz-diff")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)

	baseCfg, err := mgrconfig.LoadFile(*flagBaseConfig)
	if err != nil {
		log.Fatalf("base config: %v", err)
	}

	ctx := vm.ShutdownCtx()
	base := setup(ctx, "base", baseCfg)

	newCfg, err := mgrconfig.LoadFile(*flagNewConfig)
	if err != nil {
		log.Fatalf("new config: %v", err)
	}

	if *flagPatch != "" {
		data, err := os.ReadFile(*flagPatch)
		if err != nil {
			log.Fatal(err)
		}
		extractModifiedFiles(newCfg, data)
	}

	new := setup(ctx, "new", newCfg)
	go func() {
		new.candidates <- manager.LoadSeeds(newCfg, true).Candidates
	}()

	stream := queue.NewRandomQueue(4096, rand.New(rand.NewSource(time.Now().UnixNano())))
	base.source = stream
	new.duplicateInto = stream

	store := &manager.DiffFuzzerStore{BasePath: new.cfg.Workdir}
	diffCtx := &diffContext{
		doneRepro:     make(chan *manager.ReproResult),
		base:          base,
		new:           new,
		store:         store,
		reproAttempts: map[string]int{},
	}
	if newCfg.HTTP != "" {
		diffCtx.http = &manager.HTTPServer{
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
	diffCtx.Loop(ctx)
}

type diffContext struct {
	store *manager.DiffFuzzerStore
	http  *manager.HTTPServer

	doneRepro chan *manager.ReproResult
	base      *kernelContext
	new       *kernelContext

	mu            sync.Mutex
	reproAttempts map[string]int
}

func (dc *diffContext) Loop(ctx context.Context) {
	reproLoop := manager.NewReproLoop(dc, dc.new.pool.Total()-dc.new.cfg.FuzzingVMs, false)
	if dc.http != nil {
		dc.http.ReproLoop = reproLoop
		go dc.http.Serve()
	}
	go func() {
		// Let both base and patched instances somewhat progress in fuzzing before we take
		// VMs away for bug reproduction.
		// TODO: determine the exact moment of corpus triage.
		time.Sleep(15 * time.Minute)
		log.Logf(0, "starting bug reproductions")
		reproLoop.Loop(ctx)
	}()

	go dc.base.Loop()
	go dc.new.Loop()

	runner := &reproRunner{done: make(chan reproRunnerResult, 2), kernel: dc.base}
	rareStat := time.NewTicker(5 * time.Minute)
	for {
		select {
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
			if ret.crashTitle == "" {
				dc.store.BaseNotCrashed(ret.originalTitle)
				log.Logf(0, "patched-only: %s", ret.originalTitle)
			} else {
				dc.store.BaseCrashed(ret.originalTitle, ret.report)
				log.Logf(0, "crashes both: %s / %s", ret.originalTitle, ret.crashTitle)
			}
		case ret := <-dc.doneRepro:
			if ret.Repro != nil && ret.Repro.Report != nil {
				origTitle := ret.Crash.Report.Title
				if ret.Repro.Report.Title == origTitle {
					origTitle = "-SAME-"
				}
				log.Logf(1, "found repro for %q (orig title: %q), took %.2f minutes",
					ret.Repro.Report.Title, origTitle, ret.Stats.TotalTime.Minutes())
				go runner.Run(ret.Repro)
			} else {
				origTitle := ret.Crash.Report.Title
				log.Logf(1, "failed repro for %q, err=%s", origTitle, ret.Err)
			}
			dc.store.SaveRepro(ret)
		case rep := <-dc.new.crashes:
			crash := &manager.Crash{Report: rep}
			need := dc.NeedRepro(crash)
			log.Logf(0, "patched crashed: %v [need repro = %v]",
				rep.Title, need)
			dc.store.PatchedCrashed(rep.Title, rep.Report, rep.Output)
			if need {
				reproLoop.Enqueue(crash)
			}
		}
	}
}

// TODO: instead of this limit, consider expotentially growing delays between reproduction attempts.
const maxReproAttempts = 6

func (dc *diffContext) NeedRepro(crash *manager.Crash) bool {
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

func (dc *diffContext) RunRepro(crash *manager.Crash) *manager.ReproResult {
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
	ret := &manager.ReproResult{
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
	cfg        *mgrconfig.Config
	reporter   *report.Reporter
	fuzzer     atomic.Pointer[fuzzer.Fuzzer]
	serv       rpcserver.Server
	servStats  rpcserver.Stats
	crashes    chan *report.Report
	pool       *vm.Dispatcher
	features   flatrpc.Feature
	candidates chan []fuzzer.Candidate

	coverFilters    manager.CoverageFilters
	reportGenerator *manager.ReportGeneratorWrapper

	http          *manager.HTTPServer
	source        queue.Source
	duplicateInto queue.Executor
}

func setup(ctx context.Context, name string, cfg *mgrconfig.Config) *kernelContext {
	osutil.MkdirAll(cfg.Workdir)

	kernelCtx := &kernelContext{
		name:            name,
		ctx:             ctx,
		cfg:             cfg,
		crashes:         make(chan *report.Report, 128),
		candidates:      make(chan []fuzzer.Candidate),
		servStats:       rpcserver.NewNamedStats(name),
		reportGenerator: manager.ReportGeneratorCache(cfg),
	}

	var err error
	kernelCtx.reporter, err = report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("failed to create reporter for %q: %v", name, err)
	}

	kernelCtx.serv, err = rpcserver.New(&rpcserver.RemoteConfig{
		Config:  cfg,
		Manager: kernelCtx,
		Stats:   kernelCtx.servStats,
		Debug:   *flagDebug,
	})
	if err != nil {
		log.Fatalf("failed to create rpc server for %q: %v", name, err)
	}

	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("failed to create vm.Pool for %q: %v", name, err)
	}

	kernelCtx.pool = vm.NewDispatcher(vmPool, kernelCtx.fuzzerInstance)
	return kernelCtx
}

func (kc *kernelContext) Loop() {
	if err := kc.serv.Listen(); err != nil {
		log.Fatalf("failed to start rpc server: %v", err)
	}
	kc.pool.Loop(kc.ctx)
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

func (kc *kernelContext) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	if len(syscalls) == 0 {
		log.Fatalf("all system calls are disabled")
	}
	log.Logf(0, "%s: machine check complete", kc.name)
	kc.features = features

	var source queue.Source
	if kc.source == nil {
		source = queue.Tee(kc.setupFuzzer(features, syscalls), kc.duplicateInto)
	} else {
		source = kc.source
	}
	opts := fuzzer.DefaultExecOpts(kc.cfg, features, *flagDebug)
	return queue.DefaultOpts(source, opts)
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

	filtered := manager.FilterCandidates(<-kc.candidates, syscalls, false).Candidates
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

func (kc *kernelContext) CoverageFilter(modules []*vminfo.KernelModule) []uint64 {
	kc.reportGenerator.Init(modules)
	filters, err := manager.PrepareCoverageFilters(kc.reportGenerator, kc.cfg, false)
	if err != nil {
		log.Fatalf("failed to init coverage filter: %v", err)
	}
	kc.coverFilters = filters
	log.Logf(0, "cover filter size: %d", len(filters.ExecutorFilter))
	if kc.http != nil {
		kc.http.Cover.Store(&manager.CoverageInfo{
			Modules:         modules,
			ReportGenerator: kc.reportGenerator,
			CoverFilter:     filters.ExecutorFilter,
		})
	}
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs
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
	originalTitle string
	crashTitle    string
	report        []byte
}

func (rr *reproRunner) Run(r *repro.Result) {
	pool := rr.kernel.pool
	cnt := int(rr.running.Add(1))
	pool.ReserveForRun(min(cnt, pool.Total()))
	defer func() {
		cnt := int(rr.running.Add(-1))
		rr.kernel.pool.ReserveForRun(min(cnt, pool.Total()))
	}()

	ret := reproRunnerResult{originalTitle: r.Report.Title}

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
		log.Logf(1, "attempt #%d to run %q on base: crashed=%v", i, ret.originalTitle, crashed)
		if crashed {
			ret.crashTitle = result.Report.Title
			break
		}
	}
	if err != nil {
		log.Errorf("failed to run repro: %v", err)
		return
	}
	rr.done <- ret
}
