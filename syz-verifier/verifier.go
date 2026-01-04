// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
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

type Verifier struct {
	// Configuration
	cfg    *mgrconfig.Config
	target *prog.Target
	debug  bool

	// Kernel management
	kernels []*Kernel
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
	id              int
	name            string
	ctx             context.Context
	debug           bool
	cfg             *mgrconfig.Config
	reporter        *report.Reporter
	fresh           bool
	queueConfigured bool
	requestingMax   bool

	serv      rpcserver.Server
	servStats rpcserver.Stats

	pool    *vm.Dispatcher
	crashes chan *report.Report

	features        chan flatrpc.Feature
	enabledSyscalls chan map[*prog.Syscall]bool
	candidates      chan []fuzzer.Candidate
	reqMaxSignal    chan int
	maxSignal       chan signal.Signal
	optsChan        chan flatrpc.ExecOpts

	corpus *corpus.Corpus
	http   *manager.HTTPServer
	source queue.Source
	mu     sync.Mutex

	reportGenerator *manager.ReportGeneratorWrapper
	coverModules    []*vminfo.KernelModule  // Store modules for coverage display
	coverFilters    manager.CoverageFilters // Store coverage filters
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

	for idx, kernel := range vrf.kernels {
		Pools[kernel.name] = kernel.pool
		// Also set the first pool as default (empty key) for HTTP access without pool parameter
		if idx == 0 {
			Pools[""] = kernel.pool
		}
	}

	for idx, kernel := range vrf.kernels {
		if idx == 0 {
			if kernel.cfg.HTTP != "" {
				// Initialize HTTP server with the first kernel's configuration.
				// Currently, only kernel 0's data is used for coverage display and fuzzer state.
				vrf.http = &manager.HTTPServer{
					Cfg:       kernel.cfg,
					StartTime: time.Now(),
					Pools:     Pools,
				}
				// Cover info will be populated later in fuzzingLoop() after VMs are ready
			}
		}
	}
	eg.Go(func() error {
		vrf.preloadCorpus()
		return nil
	})
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
	log.Logf(0, "%-24v: %v (%v seeds)",
		"corpus", len(ret.Candidates), ret.SeedCount)
	return ret.Candidates
}

// corpusMinimization runs in a background goroutine (started in fuzzingLoop)
// and periodically minimizes the corpus every minute.
func (vrf *Verifier) corpusMinimization() {
	for range time.NewTicker(time.Minute).C {
		vrf.mu.Lock()
		vrf.minimizeCorpusLocked()
		vrf.mu.Unlock()
	}
}

// minimizeCorpusLocked removes redundant programs from the corpus while preserving
// all discovered coverage. Programs whose coverage is entirely contained in other
// programs are removed to keep the corpus lean and efficient.
func (vrf *Verifier) minimizeCorpusLocked() {
	cm := &manager.CorpusMinimizer{
		Corpus:         vrf.corpus,
		CorpusDB:       vrf.corpusDB,
		Cover:          vrf.cfg.Cover,
		LastMinCorpus:  vrf.lastMinCorpus,
		SaturatedCalls: vrf.saturatedCalls,
		DisabledHashes: vrf.disabledHashes,
		PhaseCheck: func() bool {
			// TODO: After adding verifier triage phase, re-enable phase check here.
			return true
		},
	}
	vrf.corpusDBMu.Lock()
	defer vrf.corpusDBMu.Unlock()
	vrf.lastMinCorpus = cm.Minimize()
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

// Loop starts the main verifier execution loop.
// It initializes the HTTP server and starts the fuzzing process.
func (vrf *Verifier) Loop(ctx context.Context) error {
	log.Logf(0, "starting programs analysis")
	g, ctx := errgroup.WithContext(ctx)
	// Reproducers are disabled in this verifier build. Run the HTTP server
	// (if configured) but do not create or start a repro loop.
	if vrf.http != nil {
		g.Go(func() error {
			return vrf.http.Serve(ctx)
		})
	}
	log.Logf(0, "starting corpus synchronization loop")
	for _, kctx := range vrf.kernels {
		kctx := kctx
		g.Go(func() error {
			kctx.loop(ctx)
			return nil
		})
	}

	// Start the fuzzing synchronization loop
	g.Go(func() error {
		vrf.fuzzingLoop(ctx)
		return nil
	})
	g.Go(func() error {
		vrf.maxSignalLoop(ctx)
		return nil
	})

	return g.Wait()

}

func (vrf *Verifier) MaxSignal() signal.Signal {
	if fuzzer := vrf.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (vrf *Verifier) maxSignalLoop(ctx context.Context) {
	log.Logf(0, "starting max signal loop")
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-vrf.reqMaxSignal:
			vrf.kernels[id].maxSignal <- vrf.MaxSignal()
		}
	}
}
func (vrf *Verifier) fuzzingLoop(ctx context.Context) {
	log.Logf(0, "starting fuzzing loop")

	// Wait for kernels to be ready and get enabled syscalls
	totalEnabledSyscalls, comparisonFeature, err := vrf.waitForKernelsReady(ctx)
	if err != nil {
		return
	}

	// Record the time of the first connection and initialize syscall stats
	vrf.firstConnect.Store(time.Now().Unix())
	statSyscalls := stat.New("syscalls", "Number of enabled syscalls", stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
	statSyscalls.Add(len(totalEnabledSyscalls))

	// Initialize corpus object after kernels are ready
	vrf.corpus = corpus.NewFocusedCorpus(context.Background(), vrf.corpusUpdates, vrf.coverFilters.Areas)

	// Initialize fuzzer object with preloaded corpus and enabled syscalls
	candidates := vrf.loadCorpus(totalEnabledSyscalls)
	fuzzerObj := vrf.createFuzzerObject(comparisonFeature, totalEnabledSyscalls, candidates)

	// Initialize HTTP server state with enabled syscalls, coverage, corpus, and fuzzer
	vrf.initializeHTTPServerState(totalEnabledSyscalls, vrf.corpus, fuzzerObj)

	// Start corpus input handler and minimization goroutines
	go vrf.corpusInputHandler(vrf.corpusUpdates)
	go vrf.corpusMinimization()

	log.Logf(0, "fuzzer started with %d candidates", len(candidates))

	// The main verifier fuzzer loop: fetch request → distributable check → build copies for all kernels → dispatch/collect → feedback → compare → repeat
	for {
		req, done := vrf.fetchNextRequest(ctx)
		if done {
			return
		}

		// Check if this request should be distributed to kernels for comparison
		if !vrf.isDistributableRequest(req) {
			req.Done(&queue.Result{Status: queue.Success})
			continue
		}

		// Distribute the same program to all kernel queues for comparison
		copies, responses, wg := vrf.buildRequestCopies(req)
		responses = vrf.dispatchAndCollect(req, copies, responses, wg)

		// Feed coverage back to fuzzer from kernel 0 only
		if feedbackResult := responses[0]; feedbackResult != nil {
			req.Done(feedbackResult)
		}

		// Compare execution results across kernels
		log.Logf(3, "comparing results for %d kernels", len(vrf.sources))
		vrf.compareResults(req, responses)
	}
}

func (vrf *Verifier) fetchNextRequest(ctx context.Context) (*queue.Request, bool) {
	for {
		select {
		case <-ctx.Done():
			return nil, true
		default:
		}

		req := vrf.fuzzer.Load().Next()
		if req != nil {
			return req, false
		}

		log.Logf(0, "no more candidates to fuzz, waiting for new candidates")
		select {
		case <-ctx.Done():
			return nil, true
		case <-time.After(time.Second):
			// Retry fetching after a short wait.
		}
	}
}

// isDistributableRequest checks if a request should be distributed to all kernels for comparison.
// Only Program-type requests without glob patterns should be distributed;
// other request types are corpus management and handled locally.
func (vrf *Verifier) isDistributableRequest(req *queue.Request) bool {
	return req.GlobPattern == "" && req.Type == flatrpc.RequestTypeProgram
}

// buildRequestCopies builds kernel-specific request copies and wires their callbacks
// to populate a responses slice. Returns the copies map (indexed by kernel ID),
// the responses slice, and a waitgroup for synchronization.
func (vrf *Verifier) buildRequestCopies(req *queue.Request) (map[int]*queue.Request, []*queue.Result, *sync.WaitGroup) {
	var wg sync.WaitGroup
	wg.Add(len(vrf.sources))
	responses := make([]*queue.Result, len(vrf.sources))
	copies := make(map[int]*queue.Request)

	for kernelID := range vrf.sources {
		var reqCopy *queue.Request
		if kernelID == 0 {
			// Kernel 0: Full request - results go back to fuzzer
			reqCopy = &queue.Request{
				Type:            req.Type,
				ExecOpts:        req.ExecOpts,
				Prog:            req.Prog,
				ReturnAllSignal: []int{}, // Collect coverage signal (new pc's only)
				ReturnError:     true,    // Ensure error info is returned
				ReturnOutput:    req.ReturnOutput,
				Stat:            req.Stat,
				Important:       req.Important,
			}
		} else {
			// Other kernels: Minimal request - only for comparison
			// Clone program to avoid data races during execution
			reqCopy = &queue.Request{
				Type:            req.Type,
				ExecOpts:        req.ExecOpts,
				Prog:            req.Prog.Clone(), // Clone to prevent data races during execution
				ReturnAllSignal: []int{},
				ReturnError:     true,
			}
		}

		// Capture kernelID in the closure
		kid := kernelID
		reqCopy.OnDone(func(r *queue.Request, res *queue.Result) bool {
			log.Logf(3, "got result for kernel:%d %s: %+v with info: %+v", kid, reqCopy.Prog.String(), res, res.Info)
			responses[kid] = res
			wg.Done()
			return true
		})
		copies[kernelID] = reqCopy
	}

	return copies, responses, &wg
}

// dispatchAndCollect submits request copies to kernel sources, waits for all to complete,
// and returns the collected responses slice.
func (vrf *Verifier) dispatchAndCollect(req *queue.Request, copies map[int]*queue.Request, responses []*queue.Result, wg *sync.WaitGroup) []*queue.Result {
	log.Logf(3, "distributing program: %s to %d kernels", req.Prog.String(), len(vrf.sources))
	for kernelID, source := range vrf.sources {
		log.Logf(3, "distributing program to kernel %d: %s", kernelID, req.Prog.String())
		source.Submit(copies[kernelID])
	}
	log.Logf(2, "distributed program to %d kernels", len(vrf.sources))
	wg.Wait()
	log.Logf(3, "all %d kernels finished execution", len(vrf.sources))
	return responses
}

// waitForKernelsReady waits for all kernels to report their enabled syscalls and features.
// Returns the intersection of enabled syscalls across all kernels, whether comparisons are supported,
// and any error that occurred.
func (vrf *Verifier) waitForKernelsReady(ctx context.Context) (map[*prog.Syscall]bool, bool, error) {
	log.Logf(0, "waiting for enabled syscalls and features")
	var totalEnabledSyscalls map[*prog.Syscall]bool
	comparisonFeature := true

	// Block until all kernels report enabled syscalls and features.
	for idx, kernel := range vrf.kernels {
		log.Logf(0, "waiting for kernel %s to be ready", kernel.cfg.Name)
		var enabledSyscalls map[*prog.Syscall]bool
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case enabledSyscalls = <-kernel.enabledSyscalls:
		}

		if idx == 0 {
			// Initialize with first kernel's syscalls
			totalEnabledSyscalls = make(map[*prog.Syscall]bool)
			for k, v := range enabledSyscalls {
				totalEnabledSyscalls[k] = v
			}
		} else {
			// Intersect: keep only syscalls enabled in ALL kernels
			for k := range totalEnabledSyscalls {
				if !enabledSyscalls[k] {
					delete(totalEnabledSyscalls, k)
				}
			}
		}

		var kernelFeatures flatrpc.Feature
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case kernelFeatures = <-kernel.features:
		}

		// Only enable if ALL kernels support it (intersection)
		comparisonFeature = comparisonFeature && (kernelFeatures&flatrpc.FeatureComparisons != 0)
		// TODO: Handle other features as needed (like fault injection, etc.)
	}

	return totalEnabledSyscalls, comparisonFeature, nil
}

// initializeHTTPServerState sets up the HTTP server with enabled syscalls, coverage info, corpus, and fuzzer after initialization.
func (vrf *Verifier) initializeHTTPServerState(totalEnabledSyscalls map[*prog.Syscall]bool, c *corpus.Corpus, fuzzerObj *fuzzer.Fuzzer) {
	if vrf.http == nil {
		return
	}

	// Store enabled syscalls
	vrf.http.EnabledSyscalls.Store(totalEnabledSyscalls)

	// Store coverage info from kernel 0
	kernel0 := vrf.kernels[0]
	if kernel0.coverModules != nil {
		log.Logf(1, "updating HTTP server with coverage info from kernel %s (filter PCs: %d)",
			kernel0.name, len(kernel0.coverFilters.ExecutorFilter))
		vrf.coverFilters = kernel0.coverFilters
		vrf.http.Cover.Store(&manager.CoverageInfo{
			Modules:         kernel0.coverModules,
			ReportGenerator: kernel0.reportGenerator,
			CoverFilter:     kernel0.coverFilters.ExecutorFilter,
		})
	}

	// Store corpus
	vrf.http.Corpus.Store(c)

	// Store fuzzer instance
	if fuzzerObj != nil {
		vrf.http.Fuzzer.Store(fuzzerObj)
	}
}

// createFuzzerObject creates and initializes a new fuzzer instance with the given configuration.
func (vrf *Verifier) createFuzzerObject(comparisonFeature bool, totalEnabledSyscalls map[*prog.Syscall]bool, candidates []fuzzer.Candidate) *fuzzer.Fuzzer {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
		Corpus:         vrf.corpus,
		Snapshot:       false,
		Coverage:       vrf.cfg.Cover,
		FaultInjection: false, // TODO: Try to enable faultFeature and see how many false positives we get.
		Comparisons:    comparisonFeature,
		Collide:        false,
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
	return fuzzerObj
}

// compareResults compares execution results across all kernels and logs any mismatches.
// TODO: Create dedicated mismatch struct similar to syz-manager crashes for better tracking and reporting.
func (vrf *Verifier) compareResults(req *queue.Request, responses []*queue.Result) {
	// Get kernel 0 result as baseline
	res0 := responses[0]
	if res0 == nil {
		return
	}

	// Compare errno results across kernels - only report true errno mismatches
	for i := 1; i < len(responses); i++ {
		res := responses[i]
		if res == nil {
			continue
		}

		// Check if any syscall has different errno
		// Only compare calls that were actually executed (not skipped/failed)
		hasMismatch := false
		mismatchCalls := []int{}
		for callIdx := 0; callIdx < len(res0.Info.Calls) && callIdx < len(res.Info.Calls); callIdx++ {
			call0 := res0.Info.Calls[callIdx]
			call1 := res.Info.Calls[callIdx]

			// Only report if errno differs between successfully executed calls
			if call0.Error != call1.Error {
				hasMismatch = true
				mismatchCalls = append(mismatchCalls, callIdx)
			}
		}

		if hasMismatch {
			log.Logf(0, "")
			log.Logf(0, "========== ERRNO MISMATCH DETECTED ==========")
			log.Logf(0, "Between: Kernel 0 (%s) and Kernel %d (%s)",
				vrf.kernels[0].cfg.Name, i, vrf.kernels[i].cfg.Name)
			log.Logf(0, "")
			log.Logf(0, "Complete Program Sequence:")
			log.Logf(0, "-------------------------------------------")

			// Serialize the entire program once to get properly formatted calls
			progLines := strings.Split(strings.TrimSpace(string(req.Prog.Serialize())), "\n")

			// Print full program with detailed call information
			for callIdx, call := range req.Prog.Calls {
				isMismatch := false
				for _, mc := range mismatchCalls {
					if mc == callIdx {
						isMismatch = true
						break
					}
				}

				prefix := "   "
				if isMismatch {
					prefix = ">>>"
				}

				// Print syscall with arguments from the serialized program
				callStr := ""
				if callIdx < len(progLines) {
					callStr = progLines[callIdx]
				} else {
					callStr = call.Meta.CallName + "(...)"
				}
				log.Logf(0, "%s [%d] %s", prefix, callIdx, callStr)

				// Print execution results
				if callIdx < len(res0.Info.Calls) && callIdx < len(res.Info.Calls) {
					call0 := res0.Info.Calls[callIdx]
					call1 := res.Info.Calls[callIdx]

					if isMismatch {
						log.Logf(0, "%s     ┌─ %s: errno=%d, flags=0x%x",
							prefix, vrf.kernels[0].cfg.Name, call0.Error, uint8(call0.Flags))
						log.Logf(0, "%s     └─ %s: errno=%d, flags=0x%x",
							prefix, vrf.kernels[i].cfg.Name, call1.Error, uint8(call1.Flags))
					} else {
						log.Logf(0, "%s     Result: errno=%d, flags=0x%x",
							prefix, call0.Error, uint8(call0.Flags))
					}
				}
				log.Logf(0, "")
			}

			log.Logf(0, "-------------------------------------------")
			log.Logf(0, "Kernel Outputs:")
			log.Logf(0, "  %s: %q", vrf.kernels[0].cfg.Name, res0.Output)
			log.Logf(0, "  %s: %q", vrf.kernels[i].cfg.Name, res.Output)
			if res0.Err != nil || res.Err != nil {
				log.Logf(0, "Execution Errors:")
				log.Logf(0, "  %s: %v", vrf.kernels[0].cfg.Name, res0.Err)
				log.Logf(0, "  %s: %v", vrf.kernels[i].cfg.Name, res.Err)
			}
			log.Logf(0, "=============================================")
			log.Logf(0, "")
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
	reps, err := kernel.runInstance(ctx, inst, injectExec)
	_, _ = kernel.serv.ShutdownInstance(index, len(reps) > 0)
	if len(reps) > 0 {
		// Just log crashes - syz-verifier focuses on behavioral differences, not crashes
		select {
		case <-ctx.Done():
		default:
			log.Logf(0, "kernel %s: VM crash detected: %s", kernel.cfg.Name, reps[0].Title)
		}
	}
	if err != nil {
		log.Errorf("#%d run failed: %s", inst.Index(), err)
	}
}

func (kernel *Kernel) runInstance(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) ([]*report.Report, error) {
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
	log.Logf(0, "kernel %s: configuring source", kernel.cfg.Name)
	opts := fuzzer.DefaultExecOpts(kernel.cfg, features, kernel.debug)
	kernel.source = queue.DefaultOpts(kernel.source, opts)
	kernel.mu.Lock()
	kernel.queueConfigured = true
	kernel.mu.Unlock()
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

	// Only store modules and filters for kernel 0 (used by fuzzer and HTTP server)
	// Other kernels only need to return PCs for their executors
	if kernel.id == 0 {
		kernel.coverModules = modules
		kernel.coverFilters = filters
	}

	for _, area := range filters.Areas {
		log.Logf(0, "kernel %s area %q: %d PCs in the cover filter",
			kernel.name, area.Name, len(area.CoverPCs))
	}
	log.Logf(0, "kernel %s executor cover filter: %d PCs", kernel.name, len(filters.ExecutorFilter))

	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func (kernel *Kernel) MaxSignal() signal.Signal {
	kernel.mu.Lock()
	if !kernel.queueConfigured {
		kernel.mu.Unlock()
		return nil
	}
	if kernel.requestingMax {
		kernel.mu.Unlock()
		return nil
	}
	kernel.requestingMax = true
	kernel.mu.Unlock()

	kernel.reqMaxSignal <- kernel.id
	sig := <-kernel.maxSignal

	kernel.mu.Lock()
	kernel.requestingMax = false
	kernel.mu.Unlock()

	return sig
}

func (kernel *Kernel) BugFrames() (leaks, races []string) {
	return nil, nil
}
