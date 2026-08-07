// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/execbackend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"golang.org/x/sync/errgroup"
)

// RunnerManager manages a pool of persistent syz-executor VM instances for aflow.
// It acts as an rpcserver.Manager, orchestrating the execution of specific Syzlang
// programs on demand via a synchronous Submit/SubmitBatch API.
type RunnerManager struct {
	mu         sync.Mutex
	cfg        *mgrconfig.Config
	backend    execbackend.Server
	vmPool     *vm.Pool
	dispatcher *vm.Dispatcher
	source     *queue.PlainQueue

	reporter *report.Reporter

	debug  bool
	readyC chan struct{}

	crashes []*report.Report

	ctx context.Context
}

func newRunnerManager(ctx context.Context, cfg *mgrconfig.Config, debug bool) (*RunnerManager, error) {
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter: %w", err)
	}

	rm := &RunnerManager{
		cfg:      cfg,
		reporter: reporter,
		debug:    debug,
		source:   queue.Plain(),
		readyC:   make(chan struct{}),
		ctx:      ctx,
	}
	return rm, nil
}

// Config returns the configuration used to initialize the RunnerManager.
func (rm *RunnerManager) Config() *mgrconfig.Config {
	return rm.cfg
}

// RunIsolatedManager boots a temporary, isolated RunnerManager with the specified cfg,
// executes the provided action callback, and cleans up the manager and VMs afterwards.
func RunIsolatedManager(ctx context.Context, cfg *mgrconfig.Config, debug bool,
	action func(*RunnerManager) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rm, err := newRunnerManager(ctx, cfg, debug)
	if err != nil {
		return fmt.Errorf("failed to create isolated RunnerManager: %w", err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- rm.Loop()
	}()

	// Wait for the manager to be ready or fail.
	select {
	case <-rm.readyC:
	case err := <-errc:
		if err != nil {
			return fmt.Errorf("isolated RunnerManager loop failed: %w", err)
		}
		return fmt.Errorf("isolated RunnerManager loop exited prematurely")
	case <-ctx.Done():
		return ctx.Err()
	}

	// Execute the user action.
	actionErr := action(rm)

	// Cancel the manager context to trigger shutdown.
	cancel()

	// Wait for the manager loop to exit cleanly.
	<-errc

	return actionErr
}

func (rm *RunnerManager) Loop() error {
	rpcCfg := &rpcserver.RemoteConfig{
		Config:  rm.cfg,
		Manager: rm,
		Stats:   rpcserver.NewNamedStats("aflow-runner"),
		Debug:   rm.debug,
	}
	backend, err := execbackend.New(rpcCfg)
	if err != nil {
		return fmt.Errorf("failed to create execbackend server: %w", err)
	}
	if rm.cfg.Snapshot {
		snapCfg := execbackend.SnapshotConfig{
			Config: rm.cfg,
			Stats:  rpcCfg.Stats,
		}
		backend = execbackend.NewSnapshotBackend(backend, snapCfg)
	}
	rm.backend = backend
	defer rm.backend.Close()

	vmPool, err := vm.Create(rm.cfg, rm.debug)
	if err != nil {
		return fmt.Errorf("failed to create vm.Pool: %w", err)
	}
	if vmPool.Count() == 0 {
		vmPool.Close()
		return fmt.Errorf("no VMs available in pool")
	}
	rm.vmPool = vmPool
	defer rm.vmPool.Close()

	rm.dispatcher = dispatcher.NewPool(rm.vmPool.Count(), rm.vmPool.Create, rm.executorInstance)

	if err := rm.backend.Setup(); err != nil {
		return fmt.Errorf("failed to setup execbackend: %w", err)
	}

	eg, egCtx := errgroup.WithContext(rm.ctx)

	eg.Go(func() error {
		err := rm.backend.Serve(egCtx)
		if err != nil && egCtx.Err() == nil {
			log.Logf(0, "aflow RunnerManager rpc server stopped: %v", err)
		}
		return err
	})

	eg.Go(func() error {
		rm.dispatcher.Loop(egCtx)
		return nil
	})

	eg.Go(func() error {
		// Wait for MachineChecked to be called (handshake completion)
		select {
		case <-rm.readyC:
			return nil
		case <-egCtx.Done():
			return egCtx.Err()
		case <-time.After(5 * time.Minute):
			return fmt.Errorf("timeout waiting for syz-executor to connect")
		}
	})

	return eg.Wait()
}

// executorInstance is the lifecycle callback used by the vm.Dispatcher.
// It registers the VM with the rpcserver, runs the executor binary, and catches any crashes.
func (rm *RunnerManager) executorInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	reps, err := rm.backend.RunRequests(ctx, inst, rm.reporter, updInfo)

	if len(reps) > 0 {
		log.Logf(0, "RunnerManager VM crash detected: %s", reps[0].Title)
		rm.mu.Lock()
		rm.crashes = append(rm.crashes, reps[0])
		rm.mu.Unlock()
	}
	if err != nil {
		log.Logf(0, "RunnerManager run failed: %v", err)
	}
}

func (rm *RunnerManager) RecentCrashes() []*report.Report {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	res := make([]*report.Report, len(rm.crashes))
	copy(res, rm.crashes)
	return res
}

// Submit sends a Syzlang program to the persistent syz-executor VM pool.
// It blocks until the execution finishes or the context is canceled.
func (rm *RunnerManager) Submit(
	ctx context.Context, p *prog.Prog,
) (*queue.Result, error) {
	res, err := rm.SubmitBatch(ctx, []*prog.Prog{p})
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

// SubmitBatch sends a batch of Syzlang programs to the persistent syz-executor VM pool.
// It blocks until all executions finish or the context is canceled.
func (rm *RunnerManager) SubmitBatch(
	ctx context.Context, progs []*prog.Prog,
) ([]*queue.Result, error) {
	if len(progs) == 0 {
		return nil, nil
	}

	results := make([]*queue.Result, len(progs))
	var wg sync.WaitGroup
	wg.Add(len(progs))

	for i, p := range progs {
		req := &queue.Request{
			Type: flatrpc.RequestTypeProgram,
			Prog: p.Clone(),
			ExecOpts: flatrpc.ExecOpts{
				// We force threaded mode to allow blocking calls to not hang the
				// persistent VM pool execution. Cover and signal collection are always
				// requested for aflow seed generation.
				ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagThreaded,
			},
			ReturnError:  true,
			ReturnOutput: true,
		}

		idx := i
		req.OnDone(func(r *queue.Request, res *queue.Result) bool {
			results[idx] = res
			if !rm.cfg.Snapshot {
				res.Output = append([]byte("WARNING: only executor output\n"), res.Output...)
			}
			wg.Done()
			return true
		})

		rm.source.Submit(req)
	}

	doneC := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneC)
	}()

	select {
	case <-rm.ctx.Done():
		return nil, rm.ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-doneC:
		return results, nil
	}
}

// MachineChecked implements the fuzzer.Manager interface.
func (rm *RunnerManager) MachineChecked(
	features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool,
) error {
	if len(enabledSyscalls) == 0 {
		log.Logf(0, "aflow: no syscalls enabled for runner")
		return nil
	}

	opts := fuzzer.DefaultExecOpts(rm.cfg, features, rm.debug)
	src := queue.DefaultOpts(rm.source, opts)
	rm.backend.SetSource(src)

	rm.mu.Lock()
	defer rm.mu.Unlock()
	select {
	case <-rm.readyC:
	default:
		close(rm.readyC)
	}
	return nil
}

func (rm *RunnerManager) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	return []uint64{}, nil
}

func (rm *RunnerManager) MaxSignal() signal.Signal {
	return nil
}

func (rm *RunnerManager) BugFrames() (leaks, races []string) {
	return nil, nil
}
