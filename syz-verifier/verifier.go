// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

// Constants for kernel phases
const (
	kPhaseInit = iota
	kPhaseAwaitingQueue
	kPhaseLoadedQueue
	kPhaseAwaitingMaxSignal
)

// Constants for verifier phases
const (
	vrfPhaseInit = iota
	vrfPhaseComparing
	vrfPhaseFuzzing
)

type Verifier struct {
	// Configuration
	cfg    *mgrconfig.Config
	target *prog.Target
	debug  bool
	phase  int

	// Kernel management
	kernels map[int]*Kernel
	sources map[int]*queue.PlainQueue

	// HTTP server
	http *manager.HTTPServer

	// Syscall management
	saturatedCalls    map[string]bool
	progGeneratorInit sync.WaitGroup

	// Statistics and monitoring
	servStats    rpcserver.Stats
	firstConnect atomic.Int64 // unix time, or 0 if not connected

	// Synchronization
	mu sync.Mutex

	// Corpus management
	fresh          bool
	corpus         *corpus.Corpus
	corpusDB       *db.DB
	corpusDBMu     sync.Mutex
	corpusUpdates  chan corpus.NewItemEvent
	corpusPreload  chan []fuzzer.Candidate
	syncTicker     *time.Ticker
	disabledHashes map[string]struct{}
	lastMinCorpus  int

	// Fuzzing
	fuzzer       atomic.Pointer[fuzzer.Fuzzer]
	coverFilters manager.CoverageFilters
	reqMaxSignal chan int
}

// Kernel represents a single kernel configuration in the verification process.
type Kernel struct {
	id       int
	name     string
	ctx      context.Context
	debug    bool
	cfg      *mgrconfig.Config
	reporter *report.Reporter
	fresh    bool
	phase    int

	serv      rpcserver.Server
	servStats rpcserver.Stats

	pool    *vm.Dispatcher
	crashes chan *report.Report

	features        chan flatrpc.Feature
	enabledSyscalls chan map[*prog.Syscall]bool
	candidates      chan []fuzzer.Candidate
	corpusUpdates   chan corpus.NewItemEvent
	reqMaxSignal    chan int
	maxSignal       chan signal.Signal
	optsChan        chan flatrpc.ExecOpts

	corpus *corpus.Corpus
	http   *manager.HTTPServer
	source queue.Source
	mu     sync.Mutex

	reportGenerator *manager.ReportGeneratorWrapper
}

// =============================================================================
// Verifier
// =============================================================================

func (vrf *Verifier) RunVerifierFuzzer(ctx context.Context) error {
	log.Logf(0, "starting verifier fuzzer")
	eg, ctx := errgroup.WithContext(ctx)
	Pools := make(map[string]*vm.Dispatcher, len(vrf.kernels))

	// Initialize corpus synchronization
	vrf.corpusUpdates = make(chan corpus.NewItemEvent, 256)

	for _, kernel := range vrf.kernels {
		Pools[kernel.name] = kernel.pool
		// Initialize verifier notification channel for each kernel
		kernel.corpusUpdates = vrf.corpusUpdates
	}

	for idx, kernel := range vrf.kernels {
		if idx == 0 {
			if kernel.cfg.HTTP != "" {
				// Initialize HTTP server with the first kernel's configuration
				// TODO: Enhance to aggregate information from all kernels
				vrf.http = &manager.HTTPServer{
					Cfg:       kernel.cfg,
					StartTime: time.Now(),
					Pools:     Pools,
				}
			}
		}
	}
	go vrf.preloadCorpus()
	eg.Go(func() error {
		log.Logf(0, "starting vrf loop")
		return vrf.Loop(ctx)
	})
	return eg.Wait()
}

func (vrf *Verifier) preloadCorpus() {
	log.Logf(0, "preloading corpus")
	info, err := manager.LoadSeeds(vrf.cfg, false)
	if err != nil {
		log.Fatalf("failed to load seeds")
	}
	vrf.fresh = info.Fresh
	vrf.corpusDB = info.CorpusDB
	vrf.corpusPreload <- info.Candidates
	log.Logf(0, "preloaded %d candidate", len(info.Candidates))
}

func (vrf *Verifier) loadCorpus(enabledSyscalls map[*prog.Syscall]bool) []fuzzer.Candidate {
	ret := manager.FilterCandidates(<-vrf.corpusPreload, enabledSyscalls, true)
	if vrf.cfg.PreserveCorpus {
		for _, hash := range ret.ModifiedHashes {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			vrf.disabledHashes[hash] = struct{}{}
		}
	}
	// Let's favorize smaller programs, otherwise the poorly minimized ones may overshadow the rest.
	sort.SliceStable(ret.Candidates, func(i, j int) bool {
		return len(ret.Candidates[i].Prog.Calls) < len(ret.Candidates[j].Prog.Calls)
	})
	reminimized := ret.ReminimizeSubset()
	resmashed := ret.ResmashSubset()
	log.Logf(0, "%-24v: %v (%v seeds), %d to be reminimized, %d to be resmashed",
		"corpus", len(ret.Candidates), ret.SeedCount, reminimized, resmashed)
	return ret.Candidates
}

func (vrf *Verifier) corpusMinimization() {
	for range time.NewTicker(time.Minute).C {
		vrf.mu.Lock()
		vrf.minimizeCorpusLocked()
		vrf.mu.Unlock()
	}
}

func (vrf *Verifier) minimizeCorpusLocked() {
	// Don't minimize corpus until we have triaged all inputs from it.
	// During corpus triage it would happen very often since we are actively adding inputs,
	// and presumably the persistent corpus was reasonably minimial, and we don't use it for fuzzing yet.
	// if vrf.phase < phaseTriagedCorpus {
	// 	return
	// }
	currSize := vrf.corpus.StatProgs.Val()
	if currSize <= vrf.lastMinCorpus*103/100 {
		return
	}
	vrf.corpus.Minimize(vrf.cfg.Cover)
	newSize := vrf.corpus.StatProgs.Val()

	log.Logf(1, "minimized corpus: %v -> %v", currSize, newSize)
	vrf.lastMinCorpus = newSize

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range vrf.corpus.CallCover() {
		if vrf.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.Count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.Count < 3000 && len(info.Cover)/info.Count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.Count < 300 {
				continue
			}
		}
		if vrf.saturatedCalls[call] {
			continue
		}
		vrf.saturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	vrf.corpusDBMu.Lock()
	defer vrf.corpusDBMu.Unlock()
	for key := range vrf.corpusDB.Records {
		ok1 := vrf.corpus.Item(key) != nil
		_, ok2 := vrf.disabledHashes[key]
		if !ok1 && !ok2 {
			vrf.corpusDB.Delete(key)
		}
	}
	if err := vrf.corpusDB.Flush(); err != nil {
		log.Fatalf("failed to save corpus database: %v", err)
	}
	vrf.corpusDB.BumpVersion(manager.CurrentDBVersion)
}

func (vrf *Verifier) corpusInputHandler(updates <-chan corpus.NewItemEvent) {
	for update := range updates {
		//TODO : add filtering logic here
		vrf.corpusDBMu.Lock()
		vrf.corpusDB.Save(update.Sig, update.ProgData, 0)
		if err := vrf.corpusDB.Flush(); err != nil {
			log.Errorf("failed to save corpus database: %v", err)
		}
		vrf.corpusDBMu.Unlock()
	}
}

func (vrf *Verifier) NeedRepro(crash *manager.Crash) bool {
	//TODO: implement this
	return true
}
func (vrf *Verifier) ResizeReproPool(size int) {
	// No-op implementation for syz-verifier
}

func (vrf *Verifier) RunRepro(ctx context.Context, crash *manager.Crash) *manager.ReproResult {
	// Minimal implementation for syz-verifier
	return &manager.ReproResult{
		Crash: crash,
		Repro: nil,
		Stats: nil,
		Err:   fmt.Errorf("reproduction not implemented in syz-verifier"),
	}
}

// Loop starts the main verifier execution loop.
// It initializes the reproduction loop, HTTP server, and starts the fuzzing process.
func (vrf *Verifier) Loop(ctx context.Context) error {
	log.Logf(0, "starting programs analysis")
	g, ctx := errgroup.WithContext(ctx)
	// 1 vm for repro for each kernel
	reproLoop := manager.NewReproLoop(vrf, len(vrf.kernels), false)
	if vrf.http != nil {
		vrf.http.ReproLoop = reproLoop
		g.Go(func() error {
			return vrf.http.Serve(ctx)
		})
	}
	log.Logf(0, "starting corpus handler")
	go vrf.corpusInputHandler(vrf.corpusUpdates)
	// TODO: start corpus minimization loop
	g.Go(func() error {
		select {
		case <-ctx.Done():
			return nil
		default: // need to make sure this is right
		}
		log.Logf(0, "starting bug reproductions")
		reproLoop.Loop(ctx)
		return nil
	})
	log.Logf(0, "starting corpus synchronization loop")
	for _, kctx := range vrf.kernels {
		go kctx.loop(ctx)
	}

	// Start the fuzzing synchronization loop
	go vrf.fuzzingLoop(ctx)
	go vrf.maxSignalLoop(ctx)

	return g.Wait()

}

func (vrf *Verifier) MaxSignal() signal.Signal {
	if fuzzer := vrf.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (vrf *Verifier) maxSignalLoop(ctx context.Context) {
	log.Logf(0, "starting corpus synchronization loop")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		id := <-vrf.reqMaxSignal
		vrf.kernels[id].maxSignal <- vrf.MaxSignal()
	}

}
func (vrf *Verifier) fuzzingLoop(ctx context.Context) {
	log.Logf(0, "starting fuzzing loop")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if vrf.phase < vrfPhaseFuzzing {
			log.Logf(0, "waiting for enabled syscalls and features")
			totalEnabledSyscalls := make(map[*prog.Syscall]bool)
			faultFeature := false
			compariosonFeature := false
			for _, kernel := range vrf.kernels {
				if kernel.phase <= kPhaseAwaitingQueue {
					log.Logf(0, "waiting for kernel %s to be ready", kernel.cfg.Name)
					enabledSyscalls := <-kernel.enabledSyscalls
					for k, v := range enabledSyscalls {
						totalEnabledSyscalls[k] = v && totalEnabledSyscalls[k] // merge enabled syscalls
					}
					kernelFeatures := <-kernel.features
					faultFeature = ((kernelFeatures & flatrpc.FeatureFault) == 1) && faultFeature
					compariosonFeature = ((kernelFeatures & flatrpc.FeatureComparisons) == 1) && compariosonFeature
				}
			}

			vrf.http.EnabledSyscalls.Store(vrf.cfg.EnabledSyscalls)
			vrf.firstConnect.Store(time.Now().Unix())
			statSyscalls := stat.New("syscalls", "Number of enabled syscalls", stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
			statSyscalls.Add(len(totalEnabledSyscalls))
			candidates := vrf.loadCorpus(totalEnabledSyscalls)
			corpusUpdates := make(chan corpus.NewItemEvent, 128)
			vrf.corpus = corpus.NewFocusedCorpus(context.Background(),
				corpusUpdates, vrf.coverFilters.Areas)
			vrf.http.Corpus.Store(vrf.corpus)

			rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
			fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
				Corpus:         vrf.corpus,
				Snapshot:       vrf.cfg.Snapshot,
				Coverage:       vrf.cfg.Cover,
				FaultInjection: faultFeature,
				Comparisons:    compariosonFeature,
				Collide:        true,
				EnabledCalls:   totalEnabledSyscalls,
				NoMutateCalls:  vrf.cfg.NoMutateCalls,
				FetchRawCover:  vrf.cfg.RawCover,
				Logf: func(level int, msg string, args ...interface{}) {
					if level != 0 {
						return
					}
					log.Logf(level, msg, args...)
				},
				NewInputFilter: func(call string) bool {
					vrf.mu.Lock()
					defer vrf.mu.Unlock()
					return !vrf.saturatedCalls[call]
				},
			}, rnd, vrf.target)
			fuzzerObj.AddCandidates(candidates)
			vrf.fuzzer.Store(fuzzerObj)
			vrf.http.Fuzzer.Store(fuzzerObj)
			go vrf.corpusInputHandler(corpusUpdates)
			go vrf.corpusMinimization()
			vrf.phase = vrfPhaseFuzzing
			log.Logf(0, "fuzzer started with %d candidates", len(candidates))
		}
		if vrf.phase == vrfPhaseFuzzing {
			req := vrf.fuzzer.Load().Next()
			if req == nil {
				log.Logf(0, "no more candidates to fuzz, waiting for new candidates")
				// Wait for new candidates to be added.
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}

			// Distribute the same request to all kernel queues
			var wg sync.WaitGroup
			wg.Add(len(vrf.sources))
			distributed := 0
			log.Logf(3, "distributing program: %s to %d kernels", req.Prog.String(), len(vrf.sources))
			for kernelID, source := range vrf.sources {
				log.Logf(3, "distributing program to kernel %d: %s", kernelID, req.Prog.String())
				reqCopy := &queue.Request{
					Type:            req.Type,
					ExecOpts:        req.ExecOpts,
					Prog:            req.Prog,
					BinaryFile:      req.BinaryFile,
					GlobPattern:     req.GlobPattern,
					ReturnAllSignal: req.ReturnAllSignal,
					ReturnError:     req.ReturnError,
					ReturnOutput:    req.ReturnOutput,
					Stat:            req.Stat,
					Important:       req.Important,
					Avoid:           req.Avoid,
				}
				reqCopy.OnDone(func(req *queue.Request, res *queue.Result) bool {
					log.Logf(3, "got result for kernel:%d %s: %v", kernelID, reqCopy.Prog.String(), res)
					wg.Done()
					return true
				})
				source.Submit(reqCopy)
				distributed++
			}
			log.Logf(2, "distributed program to %d kernels", distributed)
			wg.Wait()
			log.Logf(3, "all %d kernels finished execution", len(vrf.sources))
			log.Logf(3, "comparing results for %d kernels", len(vrf.sources))
			// TODO: Implement result comparison logic to detect behavioral differences

		}
	}
}

// =============================================================================
// Kernel
// =============================================================================

func (kernel *Kernel) FuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	index := inst.Index()
	injectExec := make(chan bool, 10)
	kernel.serv.CreateInstance(index, injectExec, updInfo)
	rep, err := kernel.runInstance(ctx, inst, injectExec)
	lastExec, _ := kernel.serv.ShutdownInstance(index, rep != nil)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		select {
		case kernel.crashes <- rep:
		case <-ctx.Done():
		}
	}
	if err != nil {
		log.Errorf("#%d run failed: %s", inst.Index(), err)
	}
}

func (kernel *Kernel) runInstance(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) (*report.Report, error) {
	fwdAddr, err := inst.Forward(kernel.serv.Port())
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}
	executorBin, err := inst.Copy(kernel.cfg.ExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %w", err)
	}
	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manager's address")
	}
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	ctxTimeout, cancel := context.WithTimeout(ctx, kernel.cfg.Timeouts.VMRunningTime)
	defer cancel()
	_, rep, err := inst.Run(ctxTimeout, kernel.reporter, cmd,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			kernel.serv.StopFuzzing(inst.Index())
		}),
	)
	return rep, err
}

func (kernel *Kernel) MachineChecked(features flatrpc.Feature,
	enabledSyscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(enabledSyscalls) == 0 {
		log.Logf(0, "no syscalls enabled for kernel %s", kernel.cfg.Name)
		return nil, nil
	}
	log.Logf(0, "kernel %s: sending enabled syscalls: %v", kernel.cfg.Name, enabledSyscalls)
	kernel.enabledSyscalls <- enabledSyscalls

	log.Logf(0, "kernel %s: sending features: %v", kernel.cfg.Name, features)
	kernel.features <- features
	if kernel.http != nil {
		kernel.http.EnabledSyscalls.Store(enabledSyscalls)
		kernel.http.Corpus.Store(kernel.corpus)
	}
	// TODO: Aggregate to main HTTP server instead of per-kernel
	if kernel.cfg.Snapshot {
		log.Logf(0, "restarting VMs for snapshot mode")
		// kernel.snapshotSource = queue.Distribute(source)
		// kernel.Pool.SetDefault(kernel.snapshotInstance)
		kernel.serv.Close()
		kernel.serv = nil
		return queue.Callback(func() *queue.Request {
			return nil
		}), nil
	}
	kernel.setPhaseLocked(kPhaseAwaitingQueue)
	log.Logf(0, "kernel %s: configuring source", kernel.cfg.Name)
	opts := fuzzer.DefaultExecOpts(kernel.cfg, features, kernel.debug)
	kernel.source = queue.DefaultOpts(kernel.source, opts)
	kernel.setPhaseLocked(kPhaseLoadedQueue)
	return kernel.source, nil
}

func (kernel *Kernel) loop(baseCtx context.Context) {
	defer log.Logf(1, "syz-verifier (%s): kernel context loop terminated", kernel.cfg.Name)
	if err := kernel.serv.Listen(); err != nil {
		log.Fatalf("failed to start rpc server: %v", err)
	}
	ctx := vm.ShutdownCtx()
	go func() {
		err := kernel.serv.Serve(ctx)
		if err != nil {
			log.Fatalf("%s", err)
		}
	}()
	log.Logf(0, "serving rpc on tcp://%v", kernel.serv.Port())
	kernel.pool.Loop(ctx)
}

func (kernel *Kernel) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	kernel.reportGenerator.Init(modules)
	filters, err := manager.PrepareCoverageFilters(kernel.reportGenerator, kernel.cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	// kernel.coverFilters = filters. TODO: aggregate to manager
	for _, area := range filters.Areas {
		log.Logf(0, "area %q: %d PCs in the cover filter",
			area.Name, len(area.CoverPCs))
	}
	log.Logf(0, "executor cover filter: %d PCs", len(filters.ExecutorFilter))
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func (kernel *Kernel) MaxSignal() signal.Signal {
	if kernel.phase >= kPhaseLoadedQueue {
		kernel.reqMaxSignal <- kernel.id
		kernel.setPhaseLocked(kPhaseAwaitingMaxSignal)
		return <-kernel.maxSignal
	}
	return nil
}

func (kernel *Kernel) setPhaseLocked(newPhase int) {
	if kernel.phase == newPhase {
		panic("repeated phase update")
	}
	kernel.phase = newPhase
}

func (kernel *Kernel) BugFrames() (leaks, races []string) {
	return nil, nil
}
