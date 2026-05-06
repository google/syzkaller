// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/prog/test"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	diffCtx *diffContext
	base    *MockKernel
	new     *MockKernel
	done    chan error
}

func newTestEnv(t *testing.T, cfg *Config) *testEnv {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Store == nil {
		cfg.Store = &manager.DiffFuzzerStore{BasePath: t.TempDir()}
	}
	if cfg.PatchedOnly == nil {
		cfg.PatchedOnly = make(chan *Bug, 1)
	}
	if cfg.BaseCrashes == nil {
		cfg.BaseCrashes = make(chan string, 1)
	}
	if cfg.runner == nil {
		// Default to a no-op runner if none provided.
		cfg.runner = newMockRunner(nil)
	}

	diffCtx := &diffContext{
		cfg:           *cfg,
		doneRepro:     make(chan *manager.ReproResult, 1),
		store:         cfg.Store,
		reproAttempts: map[string]int{},
		patchedOnly:   cfg.PatchedOnly,
	}

	base := &MockKernel{
		CrashesCh: make(chan *report.Report, 1),
		LoopFunc:  func(ctx context.Context) error { return nil },
	}
	newKernel := &MockKernel{
		CrashesCh: make(chan *report.Report, 1),
		LoopFunc:  func(ctx context.Context) error { return nil },
	}

	newKernel.PoolVal = dispatcher.NewPool[*vm.Instance](1, func(ctx context.Context, index int) (*vm.Instance, error) {
		return &vm.Instance{}, nil
	}, func(ctx context.Context, inst *vm.Instance, upd dispatcher.UpdateInfo) {
	})
	newKernel.ConfigVal = &mgrconfig.Config{}

	diffCtx.base = base
	diffCtx.new = newKernel

	ctx, cancel := context.WithCancel(context.Background())

	return &testEnv{
		t:       t,
		ctx:     ctx,
		cancel:  cancel,
		diffCtx: diffCtx,
		base:    base,
		new:     newKernel,
		done:    make(chan error, 1),
	}
}

func (env *testEnv) start() {
	go func() {
		env.done <- env.diffCtx.Loop(env.ctx)
	}()
}

func (env *testEnv) close() {
	env.cancel()
	select {
	case <-env.done:
	case <-time.After(5 * time.Second):
		env.t.Error("timeout waiting for diffCtx loop to exit")
	}
}

func (env *testEnv) waitForStatus(title string, status manager.DiffBugStatus) {
	env.t.Helper()
	start := time.Now()
	for time.Since(start) < 15*time.Second {
		for _, bug := range env.diffCtx.store.List() {
			if bug.Title == title && bug.Status == status {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	env.t.Fatalf("timed out waiting for status: %s", status)
}

type MockKernel struct {
	LoopFunc          func(ctx context.Context) error
	CrashesCh         chan *report.Report
	TriageProgressVal float64
	ProgsPerAreaVal   map[string]int
	CoverFiltersVal   manager.CoverageFilters
	ConfigVal         *mgrconfig.Config
	PoolVal           *vm.Dispatcher
	FeaturesVal       flatrpc.Feature
	ReporterVal       *report.Reporter
}

func (mk *MockKernel) Loop(ctx context.Context) error {
	if mk.LoopFunc != nil {
		return mk.LoopFunc(ctx)
	}
	<-ctx.Done()
	return nil
}

func (mk *MockKernel) Crashes() <-chan *report.Report {
	return mk.CrashesCh
}

func (mk *MockKernel) TriageProgress() float64 {
	return mk.TriageProgressVal
}

func (mk *MockKernel) ProgsPerArea() map[string]int {
	return mk.ProgsPerAreaVal
}

func (mk *MockKernel) CoverFilters() manager.CoverageFilters {
	return mk.CoverFiltersVal
}

func (mk *MockKernel) Config() *mgrconfig.Config {
	return mk.ConfigVal
}

func (mk *MockKernel) Pool() *vm.Dispatcher {
	return mk.PoolVal
}

func (mk *MockKernel) Features() flatrpc.Feature {
	return mk.FeaturesVal
}

func (mk *MockKernel) Reporter() *report.Reporter {
	return mk.ReporterVal
}

func (mk *MockKernel) FinishCorpusTriage() {
	mk.TriageProgressVal = 1.0
}

type mockRunner struct {
	runFunc func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) *reproRunnerResult
	doneCh  chan reproRunnerResult
}

func newMockRunner(cb func(context.Context, Kernel, *repro.Result, bool) *reproRunnerResult) *mockRunner {
	return &mockRunner{
		runFunc: cb,
		doneCh:  make(chan reproRunnerResult, 1),
	}
}

func (m *mockRunner) Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
	if m.runFunc != nil {
		res := m.runFunc(ctx, k, r, fullRepro)
		if res != nil {
			m.doneCh <- *res
		}
	}
}

func (m *mockRunner) Results() <-chan reproRunnerResult {
	return m.doneCh
}

func mockRepro(title string, err error) func(context.Context, []byte, repro.Environment) (
	*repro.Result, *repro.Stats, error) {
	return mockReproCallback(title, err, nil)
}

func mockReproCallback(title string, returnErr error,
	callback func()) func(context.Context, []byte, repro.Environment) (
	*repro.Result, *repro.Stats, error) {
	return func(ctx context.Context, crashLog []byte, env repro.Environment) (*repro.Result, *repro.Stats, error) {
		if callback != nil {
			callback()
		}
		if returnErr != nil {
			return nil, nil, returnErr
		}
		target, err := prog.GetTarget("test", "64")
		if err != nil {
			return nil, nil, err
		}
		return &repro.Result{
			Report: &report.Report{Title: title},
			Prog:   target.DataMmapProg(),
		}, &repro.Stats{}, nil
	}
}
