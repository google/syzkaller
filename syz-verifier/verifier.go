// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	cfg    *mgrconfig.Config
	target *prog.Target

	kernels []*Kernel
	sources map[int]*queue.PlainQueue

	http       *manager.HTTPServer
	crashStore *manager.CrashStore

	firstConnect atomic.Int64 // unix time, or 0 if not connected.

	// Corpus management - load once at startup from the first config's workdir.
	programs []*prog.Prog
}

// Kernel represents a single kernel configuration in the verification process.
type Kernel struct {
	id              int
	name            string
	debug           bool
	cfg             *mgrconfig.Config
	reporter        *report.Reporter
	queueConfigured bool

	serv      rpcserver.Server
	servStats rpcserver.Stats

	pool    *vm.Dispatcher
	crashes chan *report.Report

	features        chan flatrpc.Feature
	enabledSyscalls chan map[*prog.Syscall]bool

	source queue.Source
	mu     sync.Mutex
}

// =============================================================================
// Verifier
// =============================================================================.
func (vrf *Verifier) RunVerifierFuzzer(ctx context.Context) error {
	log.Logf(0, "starting verifier fuzzer")
	eg, ctx := errgroup.WithContext(ctx)
	if vrf.crashStore == nil {
		vrf.crashStore = manager.NewCrashStore(vrf.cfg)
	}
	Pools := make(map[string]*vm.Dispatcher, len(vrf.kernels))

	for idx, kernel := range vrf.kernels {
		Pools[kernel.name] = kernel.pool
		// Also set the first pool as default (empty key) for HTTP access without pool parameter.
		if idx == 0 {
			Pools[""] = kernel.pool
		}
	}

	for idx, kernel := range vrf.kernels {
		if idx == 0 {
			if kernel.cfg.HTTP != "" {
				// Initialize HTTP server with the first kernel's configuration.
				vrf.http = &manager.HTTPServer{
					Cfg:        kernel.cfg,
					StartTime:  time.Now(),
					CrashStore: vrf.crashStore,
					Pools:      Pools,
				}
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
	log.Logf(0, "loading corpus.db")

	info, err := manager.LoadSeeds(vrf.cfg, false)
	if err != nil {
		log.Fatalf("failed to load corpus: %v", err)
	}
	vrf.programs = make([]*prog.Prog, len(info.Candidates))
	for i, candidate := range info.Candidates {
		vrf.programs[i] = candidate.Prog
	}

	log.Logf(0, "loaded %d corpus programs for verification", len(vrf.programs))
}

// Loop starts the main verifier execution loop.
// It initializes the HTTP server and starts the fuzzing process.
func (vrf *Verifier) Loop(ctx context.Context) error {
	log.Logf(0, "starting programs analysis")
	g, ctx := errgroup.WithContext(ctx)

	if vrf.http != nil {
		g.Go(func() error {
			return vrf.http.Serve(ctx)
		})
	}
	log.Logf(0, "starting kernels listening loops")
	for _, kctx := range vrf.kernels {
		g.Go(func() error {
			kctx.loop(ctx)
			return nil
		})
	}

	// Start the fuzzing synchronization loop.
	g.Go(func() error {
		vrf.verifierLoop(ctx)
		return nil
	})

	return g.Wait()
}

func (vrf *Verifier) verifierLoop(ctx context.Context) {
	log.Logf(0, "starting fuzzing loop")

	// Wait for kernels to be ready and get enabled syscalls.
	totalEnabledSyscalls, _, err := vrf.waitForKernelsReady(ctx)
	if err != nil {
		return
	}

	// Record the time of the first connection and initialize syscall stats.
	vrf.firstConnect.Store(time.Now().Unix())
	statSyscalls := stat.New("syscalls", "Number of enabled syscalls", stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
	statSyscalls.Add(len(totalEnabledSyscalls))

	// Log enabled syscalls.
	log.Logf(1, "starting to compare %d programs from given corpus", len(vrf.programs))

	// The main verifier loop: iterate through corpus programs and compare across kernels.
	for progIdx, prog := range vrf.programs {
		// Check context.
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Logf(1, "comparing program %d/%d", progIdx+1, len(vrf.programs))
		// Create requests for all kernels.
		requests, responses, wg := vrf.createRequests(prog)

		// Distribute to all kernels.
		for kernelID, source := range vrf.sources {
			source.Submit(requests[kernelID])
		}

		// Wait for all kernels to finish.
		wg.Wait()

		// Compare execution results.
		vrf.compareResults(prog, responses)
	}
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
			// Initialize with first kernel's syscalls.
			totalEnabledSyscalls = make(map[*prog.Syscall]bool)
			for k, v := range enabledSyscalls {
				totalEnabledSyscalls[k] = v
			}
		} else {
			// Intersect: keep only syscalls enabled in ALL kernels.
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

	// Drop calls that became invalid after intersection due to missing transitive
	// resource dependencies (e.g. consumer call remains but all producers don't).
	totalEnabledSyscalls, _ = vrf.target.TransitivelyEnabledCalls(totalEnabledSyscalls)
	if vrf.http != nil {
		vrf.http.EnabledSyscalls.Store(totalEnabledSyscalls)
	}

	return totalEnabledSyscalls, comparisonFeature, nil
}

func (vrf *Verifier) saveMismatchReport(title, body string) {
	if vrf.crashStore == nil {
		return
	}
	crash := &manager.Crash{
		Report: &report.Report{
			Title:  title,
			Report: []byte(body),
			Output: []byte(body),
		},
	}
	if _, err := vrf.crashStore.SaveCrash(crash); err != nil {
		log.Logf(0, "failed to save mismatch report: %v", err)
	}
}

const executorCallNotCompletedErrno = 999

// compareResults compares execution results across all kernels and logs any mismatches.
func (vrf *Verifier) compareResults(prog *prog.Prog, responses []*queue.Result) {
	// Get kernel 0 result as baseline.
	res0 := responses[0]
	if res0 == nil {
		return
	}

	// Compare errno results across kernels - only report true errno mismatches.
	for i := 1; i < len(responses); i++ {
		res := responses[i]
		if res == nil {
			continue
		}

		// Skip if either result is missing execution info.
		if res0.Info == nil || res.Info == nil {
			continue
		}

		// Check if any syscall has different errno
		// Only compare calls that were actually executed (not skipped/failed)
		hasMismatch := false
		mismatchCalls := []int{}
		for callIdx := 0; callIdx < len(res0.Info.Calls) && callIdx < len(res.Info.Calls); callIdx++ {
			call0 := res0.Info.Calls[callIdx]
			call1 := res.Info.Calls[callIdx]

			// Errno 999 means syz-executor did not actually complete the syscall.
			// Treat such calls as not comparable.
			if call0.Error == executorCallNotCompletedErrno || call1.Error == executorCallNotCompletedErrno {
				continue
			}

			// Only report if errno differs between successfully completed calls.
			if call0.Error != call1.Error {
				hasMismatch = true
				mismatchCalls = append(mismatchCalls, callIdx)
			}
		}

		if hasMismatch {
			var reportBody strings.Builder
			writeLine := func(format string, args ...any) {
				line := fmt.Sprintf(format, args...)
				log.Logf(0, "%s", line)
				reportBody.WriteString(line)
				reportBody.WriteByte('\n')
			}

			writeLine("")
			writeLine("========== ERRNO MISMATCH DETECTED ==========")
			writeLine("Between: Kernel 0 (%s) and Kernel %d (%s)",
				vrf.kernels[0].cfg.Name, i, vrf.kernels[i].cfg.Name)
			writeLine("")
			writeLine("Complete Program Sequence:")
			writeLine("-------------------------------------------")

			// Serialize the entire program once to get properly formatted calls.
			progLines := strings.Split(strings.TrimSpace(string(prog.Serialize())), "\n")

			// Print full program with detailed call information.
			for callIdx, call := range prog.Calls {
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

				// Print syscall with arguments from the serialized program.
				callStr := ""
				if callIdx < len(progLines) {
					callStr = progLines[callIdx]
				} else {
					callStr = call.Meta.CallName + "(...)"
				}
				writeLine("%s [%d] %s", prefix, callIdx, callStr)

				// Print execution results.
				if callIdx < len(res0.Info.Calls) && callIdx < len(res.Info.Calls) {
					call0 := res0.Info.Calls[callIdx]
					call1 := res.Info.Calls[callIdx]

					if isMismatch {
						writeLine("%s     ┌─ %s: errno=%d, flags=0x%x",
							prefix, vrf.kernels[0].cfg.Name, call0.Error, uint8(call0.Flags))
						writeLine("%s     └─ %s: errno=%d, flags=0x%x",
							prefix, vrf.kernels[i].cfg.Name, call1.Error, uint8(call1.Flags))
					} else {
						writeLine("%s     Result: errno=%d, flags=0x%x",
							prefix, call0.Error, uint8(call0.Flags))
					}
				}
				writeLine("")
			}

			writeLine("-------------------------------------------")
			writeLine("Kernel Outputs:")
			writeLine("  %s: %q", vrf.kernels[0].cfg.Name, res0.Output)
			writeLine("  %s: %q", vrf.kernels[i].cfg.Name, res.Output)
			if res0.Err != nil || res.Err != nil {
				writeLine("Execution Errors:")
				writeLine("  %s: %v", vrf.kernels[0].cfg.Name, res0.Err)
				writeLine("  %s: %v", vrf.kernels[i].cfg.Name, res.Err)
			}
			writeLine("=============================================")
			writeLine("")

			firstMismatchCall := "unknown"
			if len(mismatchCalls) > 0 && mismatchCalls[0] < len(prog.Calls) {
				firstMismatchCall = prog.Calls[mismatchCalls[0]].Meta.CallName
			}
			title := fmt.Sprintf("syz-verifier errno mismatch: %s vs %s (%s)",
				vrf.kernels[0].cfg.Name, vrf.kernels[i].cfg.Name, firstMismatchCall)
			vrf.saveMismatchReport(title, reportBody.String())
		}
	}
}

// createRequests creates execution requests for all kernels for a given program.
// Returns the map of requests, a slice to collect results, and a WaitGroup to track completion.
func (vrf *Verifier) createRequests(prog *prog.Prog) (map[int]*queue.Request, []*queue.Result, *sync.WaitGroup) {
	requests := make(map[int]*queue.Request)
	responses := make([]*queue.Result, len(vrf.sources))
	var wg sync.WaitGroup
	wg.Add(len(vrf.sources))

	for kernelID := range vrf.sources {
		kid := kernelID
		// Create request for each kernel.
		reqCopy := &queue.Request{
			Type:         flatrpc.RequestTypeProgram,
			Prog:         prog.Clone(),
			ReturnError:  true, // Ensure error info is returned for comparison.
			ReturnOutput: true, // Return output for debugging mismatches.
		}

		reqCopy.OnDone(func(r *queue.Request, res *queue.Result) bool {
			log.Logf(3, "kernel %d finished executing program", kid)
			responses[kid] = res
			wg.Done()
			return true
		})
		requests[kernelID] = reqCopy
	}

	return requests, responses, &wg
}

// =============================================================================
// Kernel
// =============================================================================.
func (kernel *Kernel) FuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	index := inst.Index()
	injectExec := make(chan bool, 10)
	kernel.serv.CreateInstance(index, injectExec, updInfo)
	reps, err := kernel.runInstance(ctx, inst, injectExec)
	_, _ = kernel.serv.ShutdownInstance(index, len(reps) > 0)
	if len(reps) > 0 {
		// Just log crashes - syz-verifier focuses on behavioral differences, not crashes.
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
	log.Logf(0, "kernel %s: configuring source", kernel.cfg.Name)
	opts := fuzzer.DefaultExecOpts(kernel.cfg, features, kernel.debug)
	kernel.source = queue.DefaultOpts(kernel.source, opts)
	kernel.mu.Lock()
	kernel.queueConfigured = true
	kernel.mu.Unlock()
	return kernel.source, nil
}

func (kernel *Kernel) loop(ctx context.Context) {
	defer log.Logf(1, "syz-verifier (%s): kernel context loop terminated", kernel.cfg.Name)
	if err := kernel.serv.Listen(); err != nil {
		log.Fatalf("failed to start rpc server: %v", err)
	}
	// Respect both the caller-provided context and global shutdown.
	shutdown := vm.ShutdownCtx()
	runCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-shutdown.Done()
		cancel()
	}()
	go func() {
		err := kernel.serv.Serve(runCtx)
		if err != nil {
			log.Fatalf("%s", err)
		}
	}()
	log.Logf(0, "serving rpc on tcp://%v", kernel.serv.Port())
	kernel.pool.Loop(runCtx)
}

func (kernel *Kernel) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	// No coverage filtering needed in corpus exercise mode
	// Return empty PC set since we're not discovering coverage
	return []uint64{}, nil
}

func (kernel *Kernel) MaxSignal() signal.Signal {
	// No signal tracking in corpus exercise mode.
	return nil
}

func (kernel *Kernel) BugFrames() (leaks, races []string) {
	return nil, nil
}
