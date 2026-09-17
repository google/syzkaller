// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	_ "github.com/google/syzkaller/prog/test"
	"github.com/stretchr/testify/assert"
)

const testTimeout = 15 * time.Second

func TestNeedReproForTitle(t *testing.T) {
	for title, skip := range map[string]bool{
		"no output from test machine":                          false,
		"SYZFAIL: read failed":                                 false,
		"lost connection to test machine":                      false,
		"INFO: rcu detected stall in clone":                    true,
		"WARNING in arch_install_hw_breakpoint":                true,
		"KASAN: slab-out-of-bounds Write in __bpf_get_stackid": true,
	} {
		assert.Equal(t, skip, needReproForTitle(title), "title=%q", title)
	}
}

func TestDiffBaseCrashInterception(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.close()
	env.start()

	env.base.CrashesCh <- &report.Report{Title: "base_crash"}

	select {
	case title := <-env.diffCtx.cfg.BaseCrashes:
		assert.Equal(t, "base_crash", title)
	case <-time.After(testTimeout):
		t.Error("expected base crash")
	}
}

func TestDiffExternalIgnore(t *testing.T) {
	// Config ignores crash -> Patched crash ignored -> No repro.
	runReproCalled := false
	mockRunRepro := mockReproCallback("important_crash", nil, func() {
		runReproCalled = true
	})

	env := newTestEnv(t, &Config{
		IgnoreCrash: func(ctx context.Context, title string) (bool, error) {
			if title == "ignored_crash" {
				return true, nil
			}
			return false, nil
		},
		runRepro: mockRunRepro,
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	env.new.CrashesCh <- &report.Report{Title: "ignored_crash", Report: []byte("log")}
	env.waitForStatus("ignored_crash", manager.DiffBugStatusIgnored)
	assert.False(t, runReproCalled, "should not repro ignored crash")

	env.new.CrashesCh <- &report.Report{Title: "important_crash", Report: []byte("log")}
	env.waitForStatus("important_crash", manager.DiffBugStatusVerifying)
}

func TestDiffSuccess(t *testing.T) {
	// Patched kernel crashes -> Repro succeeds -> Base kernel does NOT crash -> PatchedOnly reported.

	// Mock Runner (Repro on Base).
	env := newTestEnv(t, &Config{
		runRepro: mockRepro("crash_title", nil),
		runner: newMockRunner(func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) *reproRunnerResult {
			// Simulate successful run on base without crash.
			return &reproRunnerResult{
				reproReport: r.Report,
				repro:       r,
				crashReport: nil, // No crash on base.
				fullRepro:   true,
			}
		}),
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	select {
	case bug := <-env.diffCtx.patchedOnly:
		assert.Equal(t, "crash_title", bug.Report.Title)
		assert.False(t, env.diffCtx.NeedRepro(&manager.Crash{Report: bug.Report}))
	case <-time.After(testTimeout):
		t.Fatal("expected patched only report")
	}
}

func TestDiffFailNoRepro(t *testing.T) {
	// Patched kernel crashes -> Repro fails -> No report.
	env := newTestEnv(t, &Config{
		runRepro: mockRepro("", errors.New("repro failed")),
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	env.waitForStatus("crash_title", manager.DiffBugStatusCompleted)
}

func TestDiffFailBaseCrash(t *testing.T) {
	// Patched kernel crashes -> Repro succeeds -> Base also crashes -> No PatchedOnly report.
	env := newTestEnv(t, &Config{
		runRepro: mockRepro("crash_title", nil),
		runner: newMockRunner(func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) *reproRunnerResult {
			return &reproRunnerResult{
				reproReport: r.Report,
				repro:       r,
				crashReport: &report.Report{Title: "crash_title"}, // Base crashed.
			}
		}),
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}

	select {
	case <-env.diffCtx.patchedOnly:
		t.Fatal("unexpected patched only report")
	case <-env.diffCtx.cfg.BaseCrashes: // Should report to BaseCrashes.
		// Expected.
	case <-time.After(testTimeout):
		t.Fatal("expected base crash report")
	}

	env.waitForStatus("crash_title", manager.DiffBugStatusCompleted)
}

func TestDiffFailBaseCrashEarly(t *testing.T) {
	// Base crashes first -> Patched crashes same title -> No reproduction attempt.
	runReproCalled := false
	mockRunRepro := mockReproCallback("crash_title", nil, func() {
		runReproCalled = true
	})

	env := newTestEnv(t, &Config{
		runRepro: mockRunRepro,
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	env.base.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	select {
	case <-env.diffCtx.cfg.BaseCrashes:
	case <-time.After(testTimeout):
		t.Fatal("expected base crash")
	}
	env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	env.waitForStatus("crash_title", manager.DiffBugStatusIgnored)
	assert.False(t, runReproCalled, "WaitRepro should not be called")
}

func TestDiffRetryRepro(t *testing.T) {
	// Patched kernel crashes -> Repro fails -> Retried until max attempts.
	reproCalled := make(chan struct{}, 10)
	mockRunRepro := mockReproCallback("", errors.New("repro failed"), func() {
		reproCalled <- struct{}{}
	})

	env := newTestEnv(t, &Config{
		runRepro: mockRunRepro,
	})
	defer env.close()

	env.new.FinishCorpusTriage()
	env.start()

	for i := range maxReproAttempts {
		env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
		select {
		case <-reproCalled:
		case <-time.After(testTimeout):
			t.Fatalf("iteration %d: expected repro", i)
		}
		env.waitForStatus("crash_title", manager.DiffBugStatusCompleted)
	}
	// Inject one more crash, which should not trigger another repro and should preserve Completed status.
	env.new.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	env.waitForStatus("crash_title", manager.DiffBugStatusCompleted)
	select {
	case <-reproCalled:
		t.Fatalf("unexpected repro")
	default:
	}
}

func TestMonitorPatchedCoverage(t *testing.T) {
	area := func(name string, pc uint64) corpus.FocusArea {
		return corpus.FocusArea{Name: name, CoverPCs: map[uint64]struct{}{pc: {}}}
	}
	// The area that lets the fuzzer still cover the rest of the kernel.
	restOfKernel := corpus.FocusArea{Weight: 1.0}
	tests := []struct {
		name    string
		areas   []corpus.FocusArea
		progs   map[string]int
		wantErr error
	}{
		{
			name:  "no focus areas",
			areas: []corpus.FocusArea{restOfKernel},
		},
		{
			name:  "patched code reached",
			areas: []corpus.FocusArea{area(symbolsArea, 1), area(filesArea, 2), restOfKernel},
			progs: map[string]int{symbolsArea: 1, "": 10},
		},
		{
			// The AI-suggested area is related enough to the patch, so keep fuzzing.
			// Note that it comes after the "rest of the kernel" one.
			name:  "only ai_focus reached",
			areas: []corpus.FocusArea{area(symbolsArea, 1), restOfKernel, area("ai_focus", 2)},
			progs: map[string]int{"ai_focus": 1, "": 10},
		},
		{
			name:    "only the rest of the kernel reached",
			areas:   []corpus.FocusArea{area(symbolsArea, 1), restOfKernel, area("ai_focus", 2)},
			progs:   map[string]int{"": 10},
			wantErr: ErrPatchedAreaNotReached,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newTestEnv(t, &Config{FuzzToReachPatched: time.Millisecond})
			env.new.FinishCorpusTriage()
			env.new.CoverFiltersVal = manager.CoverageFilters{Areas: test.areas}
			env.new.ProgsPerAreaVal = test.progs

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			assert.ErrorIs(t, env.diffCtx.monitorPatchedCoverage(ctx), test.wantErr)
		})
	}
}
