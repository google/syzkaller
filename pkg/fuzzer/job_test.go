// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
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

// syncExecutor is a queue.Executor for job unit tests that executes
// requests synchronously within Submit via the given function.
type syncExecutor func(req *queue.Request) *queue.Result

func (exec syncExecutor) Submit(req *queue.Request) {
	req.Done(exec(req))
}

func TestHintsJobSkipsRunsWithoutComps(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("test$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"), prog.Strict)
	require.NoError(t, err)

	ctx := t.Context()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$int"]: true,
		},
	}, rand.New(rand.NewSource(0)), target)

	seedRuns, hintRuns := 0, 0
	exec := syncExecutor(func(req *queue.Request) *queue.Result {
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps == 0 {
			hintRuns++
			return &queue.Result{Status: queue.Success}
		}
		seedRuns++
		call := &flatrpc.CallInfo{}
		// The first run returns no comparisons, which must not discard the following ones.
		if seedRuns > 1 {
			call.Comps = []*flatrpc.Comparison{{Pc: 1, Op1: 0x5, Op2: 0x12345678}}
		}
		return &queue.Result{
			Status: queue.Success,
			Info:   &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{call}},
		}
	})
	job := &hintsJob{exec: exec, p: p, call: 0, info: &JobInfo{}}
	job.run(fuzzer)
	assert.Equal(t, 3, seedRuns)
	assert.Positive(t, hintRuns)
}
