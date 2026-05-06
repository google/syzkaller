// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

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
	// Once candidates is assigned, candidatesCount holds their original count.
	candidatesCount atomic.Int64

	coverFilters    manager.CoverageFilters
	reportGenerator *manager.ReportGeneratorWrapper

	http          *manager.HTTPServer
	source        queue.Source
	duplicateInto queue.Executor
}

func setup(name string, cfg *mgrconfig.Config, debug bool) (*kernelContext, error) {
	osutil.MkdirAll(cfg.Workdir)

	kernelCtx := &kernelContext{
		name:            name,
		debug:           debug,
		cfg:             cfg,
		crashes:         make(chan *report.Report, 128),
		candidates:      make(chan []fuzzer.Candidate),
		servStats:       rpcserver.NewNamedStats(name),
		reportGenerator: manager.ReportGeneratorCache(cfg),
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

func (kc *kernelContext) Loop(ctx context.Context) error {
	defer log.Logf(1, "%s: kernel context loop terminated", kc.name)

	if err := kc.serv.Listen(); err != nil {
		return fmt.Errorf("failed to start rpc server: %w", err)
	}
	eg, groupCtx := errgroup.WithContext(ctx)
	kc.ctx = groupCtx
	eg.Go(func() error {
		defer log.Logf(1, "%s: rpc server terminaled", kc.name)
		return kc.serv.Serve(groupCtx)
	})
	eg.Go(func() error {
		defer log.Logf(1, "%s: pool terminated", kc.name)
		kc.pool.Loop(groupCtx)
		return nil
	})
	eg.Go(func() error {
		for {
			select {
			case <-groupCtx.Done():
				return nil
			case err := <-kc.pool.BootErrors:
				title := "unknown"
				var bootErr vm.BootErrorer
				if errors.As(err, &bootErr) {
					title, _ = bootErr.BootError()
				}
				// Boot errors are not useful for patch fuzzing (at least yet).
				// Fetch them to not block the channel and print them to the logs.
				log.Logf(0, "%s: boot error: %s", kc.name, title)
			}
		}
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
		// Fault injection may bring instaibility into bug reproducibility, which may lead to false positives.
		FaultInjection: false,
		Comparisons:    features&flatrpc.FeatureComparisons != 0,
		Collide:        true,
		EnabledCalls:   syscalls,
		NoMutateCalls:  kc.cfg.NoMutateCalls,
		PatchTest:      true,
		Logf: func(level int, msg string, args ...any) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
	}, rnd, kc.cfg.Target)

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
	// We assign kc.fuzzer after kc.candidatesCount to simplify the triageProgress implementation.
	kc.candidatesCount.Store(int64(len(candidates)))
	kc.fuzzer.Store(fuzzerObj)

	filtered := manager.FilterCandidates(candidates, syscalls, false).Candidates
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
	filters, err := manager.PrepareCoverageFilters(kc.reportGenerator, kc.cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	kc.coverFilters = filters
	for _, area := range filters.Areas {
		log.Logf(0, "area %q: %d PCs in the cover filter",
			area.Name, len(area.CoverPCs))
	}
	log.Logf(0, "executor cover filter: %d PCs", len(filters.ExecutorFilter))
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
		select {
		case kc.crashes <- rep:
		case <-ctx.Done():
		}
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
	ctxTimeout, cancel := context.WithTimeout(ctx, kc.cfg.Timeouts.VMRunningTime)
	defer cancel()
	_, reps, err := inst.Run(ctxTimeout, kc.reporter, cmd,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			kc.serv.StopFuzzing(inst.Index())
		}),
	)
	if len(reps) > 0 {
		return reps[0], err
	}
	return nil, err
}

func (kc *kernelContext) TriageProgress() float64 {
	fuzzer := kc.fuzzer.Load()
	if fuzzer == nil {
		return 0
	}
	total := kc.candidatesCount.Load()
	if total == 0.0 {
		// There were no candidates in the first place.
		return 1
	}
	return 1.0 - float64(fuzzer.CandidatesToTriage())/float64(total)
}

func (kc *kernelContext) ProgsPerArea() map[string]int {
	fuzzer := kc.fuzzer.Load()
	if fuzzer == nil {
		return nil
	}
	return fuzzer.Config.Corpus.ProgsPerArea()
}

func (kc *kernelContext) Crashes() <-chan *report.Report {
	return kc.crashes
}

func (kc *kernelContext) CoverFilters() manager.CoverageFilters {
	return kc.coverFilters
}

func (kc *kernelContext) Config() *mgrconfig.Config {
	return kc.cfg
}

func (kc *kernelContext) Pool() *vm.Dispatcher {
	return kc.pool
}

func (kc *kernelContext) Features() flatrpc.Feature {
	return kc.features
}

func (kc *kernelContext) Reporter() *report.Reporter {
	return kc.reporter
}
