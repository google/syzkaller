// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeflake(t *testing.T) {
	type Test struct {
		Info      triageCall
		Flags     ProgFlags
		PatchTest bool
		Exec      func(run uint64) (errno int32, signal []uint64, cover []uint64)
		Runs      uint64
	}
	tests := []Test{
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 1. For second, 2. And so on.
				return 0, []uint64{run}, []uint64{10, 20}
			},
			Runs: 3,
		},
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2}, 0),
				// Cover is a union of all coverages.
				cover: cover.FromRaw([]uint64{10, 20, 30, 40, 100}),
				// 0, 2, 6 were in three resuls.
				stableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
				// 0, 2 were also in newSignal.
				newStableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				switch run {
				case 1:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{10, 20}
				case 2:
					// This one should be ignored -- it has a different errno.
					return 1, []uint64{0, 1, 2}, []uint64{100}
				case 3:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{20, 30}
				case 4:
					return 0, []uint64{0, 2, 6}, []uint64{30, 40}
				}
				panic("unrechable")
			},
			Runs: 4,
		},
		{
			Info: triageCall{
				newSignal:       signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 3),
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{2}, 0),
				newStableSignal: signal.FromRaw([]uint64{2}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 0 and 1. For second, 1 and 2. And so on.
				return 0, []uint64{run, run + 1}, []uint64{10, 20}
			},
			Runs: 2,
		},
		{
			Flags: ProgFromCorpus,
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{run}, []uint64{10, 20}
			},
			// Since every run returns new signal, corpus deflake runs until deflakeTotalCorpusRuns (20).
			// Including the initial candidate run before deflake, that leaves 20 - 1 = 19 deflake runs.
			Runs: 19,
		},
		{
			Flags:     ProgFromCorpus,
			PatchTest: true,
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{run}, []uint64{10, 20}
			},
			// In PatchTest mode, deflake stops at deflakeMaxRuns (5), which is 5 - 1 = 4 deflake runs.
			Runs: 4,
		},
		{
			Flags:     ProgFromCorpus,
			PatchTest: true,
			Info: triageCall{
				newSignal:       signal.FromRaw([]uint64{0}, 0),
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{0}, 0),
				newStableSignal: signal.FromRaw([]uint64{0}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{0}, []uint64{10, 20}
			},
			// In PatchTest mode, corpus deflake stops as soon as deflakeNeedCorpusRuns (2) is reached.
			Runs: 2,
		},
	}

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	const anyTestProg = `syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void, @void}, AUTO)`
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			info := test.Info
			info.signals[0] = test.Info.newSignal.Copy()
			info.cover = nil
			info.stableSignal = nil
			info.newStableSignal = nil
			testJob := &triageJob{
				p:     prog,
				flags: test.Flags,
				calls: map[int]*triageCall{0: &info},
				fuzzer: &Fuzzer{
					Cover:  newCover(),
					Config: &Config{PatchTest: test.PatchTest},
				},
				info: &JobInfo{},
			}

			var run uint64
			stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
				run++
				errno, signal, cover := test.Exec(run)
				return &queue.Result{
					Info: &flatrpc.ProgInfo{
						Calls: []*flatrpc.CallInfo{{
							Error:  errno,
							Signal: signal,
							Cover:  cover,
						}},
					},
				}
			})

			assert.False(t, stop)
			assert.Equal(t, run, test.Runs)
			assert.ElementsMatch(t, info.cover.Serialize(), test.Info.cover.Serialize())
			assert.ElementsMatch(t, info.stableSignal.ToRaw(), test.Info.stableSignal.ToRaw())
			assert.ElementsMatch(t, info.newStableSignal.ToRaw(), test.Info.newStableSignal.ToRaw())
		})
	}
}

func TestDeterministicMinimizeFailure(t *testing.T) {
	newStable := signal.FromRaw([]uint64{100, 101}, 0)
	makeInfo := func(errno int32, sig ...uint64) *flatrpc.ProgInfo {
		return &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{{Error: errno, Signal: sig}},
		}
	}

	// Two consecutive identical non-zero errors without target signal stop early.
	var prevErr int32
	var prevSig signal.Signal
	assert.False(t, deterministicMinimizeFailure(makeInfo(22, 1, 2), newStable, 0, &prevErr, &prevSig))
	assert.True(t, deterministicMinimizeFailure(makeInfo(22, 1, 2), newStable, 0, &prevErr, &prevSig))

	// Successful calls (errno == 0) never trigger early stop so flaky coverage keeps all retries.
	prevSig = nil
	assert.False(t, deterministicMinimizeFailure(makeInfo(0, 1, 2), newStable, 0, &prevErr, &prevSig))
	assert.False(t, deterministicMinimizeFailure(makeInfo(0, 1, 2), newStable, 0, &prevErr, &prevSig))

	// Any overlap with newStableSignal keeps retrying.
	prevSig = nil
	assert.False(t, deterministicMinimizeFailure(makeInfo(22, 1, 100), newStable, 0, &prevErr, &prevSig))
	assert.False(t, deterministicMinimizeFailure(makeInfo(22, 1, 100), newStable, 0, &prevErr, &prevSig))

	// Different error signals or errnos keep retrying.
	prevSig = nil
	assert.False(t, deterministicMinimizeFailure(makeInfo(22, 1, 2), newStable, 0, &prevErr, &prevSig))
	assert.False(t, deterministicMinimizeFailure(makeInfo(22, 1, 3), newStable, 0, &prevErr, &prevSig))
}

func TestHandleCallSmashDedup(t *testing.T) {
	t.Cleanup(checkGoroutineLeaks)

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize([]byte(`test$res0()
test$int(0x1, 0x2, 0x3, 0x4, 0x5)
`), prog.Strict)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:         corpus.NewCorpus(ctx),
		Comparisons:    true,
		FaultInjection: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$res0"]: true,
			target.SyscallMap["test$int"]:  true,
		},
	}, rand.New(rand.NewSource(0)), target)

	tj := &triageJob{
		p:      p,
		flags:  ProgMinimized,
		fuzzer: fuzzer,
		info:   &JobInfo{},
	}
	tj.handleCall(0, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{1}, 0),
		newStableSignal: signal.FromRaw([]uint64{1}, 0),
		cover:           cover.FromRaw([]uint64{1}),
	})
	tj.handleCall(1, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{2}, 0),
		newStableSignal: signal.FromRaw([]uint64{2}, 0),
		cover:           cover.FromRaw([]uint64{2}),
	})

	// Both calls save the same program to the corpus: only one smashJob should be
	// started, while per-call hintsJob and faultInjectionJob run for both calls.
	assert.Equal(t, 1, fuzzer.statJobsSmash.Val())
	assert.Equal(t, 2, fuzzer.statJobsHints.Val())
	assert.Equal(t, 2, fuzzer.statJobsFaultInjection.Val())
	cancel()
}

func TestFocusedCandidateSmashAndHints(t *testing.T) {
	t.Cleanup(checkGoroutineLeaks)

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize([]byte(`test$res0()
test$int(0x1, 0x2, 0x3, 0x4, 0x5)
`), prog.Strict)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	focusCorpus := corpus.NewFocusedCorpus(ctx, nil, []corpus.FocusArea{
		{
			Name:     "symbols",
			CoverPCs: map[uint64]struct{}{0x100: {}},
			Weight:   6.0,
		},
		{
			Name:     "files",
			CoverPCs: map[uint64]struct{}{0x200: {}},
			Weight:   3.0,
		},
	})
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:      focusCorpus,
		Comparisons: true,
		PatchTest:   true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$res0"]: true,
			target.SyscallMap["test$int"]:  true,
		},
	}, rand.New(rand.NewSource(0)), target)

	// Simulate an initial diff-fuzzer candidate (which has ProgSmashed pre-set) where
	// call 0 hits unfocused kernel code and call 1 hits the focused "symbols" tier.
	tj := &triageJob{
		p:      p,
		flags:  ProgFromCorpus | ProgMinimized | ProgSmashed,
		fuzzer: fuzzer,
		info:   &JobInfo{},
	}
	tj.handleCall(0, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{0x1}, 0),
		newStableSignal: signal.FromRaw([]uint64{0x1}, 0),
		cover:           cover.FromRaw([]uint64{0x1}),
	})
	assert.Equal(t, 0, fuzzer.statJobsSmash.Val(), "unfocused call must not start smashJob")
	assert.Equal(t, 0, fuzzer.statJobsHints.Val(), "unfocused call must not start hintsJob")

	// Saturate the lower-priority "files" tier hints queue (as happens during candidate triage)
	// and verify that the "symbols" tier candidate still starts both smashJob and hintsJob.
	fuzzer.tiers[1].hintsJobs.Store(30)
	tj.handleCall(1, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{0x100}, 0),
		newStableSignal: signal.FromRaw([]uint64{0x100}, 0),
		cover:           cover.FromRaw([]uint64{0x100}),
	})
	assert.Equal(t, 1, fuzzer.statJobsSmash.Val(),
		"focused candidate call must start smashJob despite ProgSmashed and prior unfocused save")
	assert.Equal(t, 1, fuzzer.statJobsHints.Val(),
		"focused candidate call in symbols tier must not be starved by files tier hints")
	assert.Equal(t, int64(1), fuzzer.tiers[0].hintsJobs.Load())

	// A candidate in the saturated "files" tier still gets smashed (if a new prog), but its hints are capped.
	p2 := p.Clone()
	p2.Calls = p2.Calls[:1]
	tjFiles := &triageJob{
		p:      p2,
		flags:  ProgFromCorpus | ProgMinimized | ProgSmashed,
		fuzzer: fuzzer,
		info:   &JobInfo{},
	}
	tjFiles.handleCall(0, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{0x200}, 0),
		newStableSignal: signal.FromRaw([]uint64{0x200}, 0),
		cover:           cover.FromRaw([]uint64{0x200}),
	})
	assert.Equal(t, 2, fuzzer.statJobsSmash.Val())
	assert.Equal(t, 1, fuzzer.statJobsHints.Val(), "files tier hints should be capped at 30")
}
