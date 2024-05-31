// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestDeflake(t *testing.T) {
	type Test struct {
		NewSignal signal.Signal
		Exec      func(run uint64) (errno int32, signal []uint64, cover []uint64)
		Runs      uint64
		Result    deflakedCover
	}
	tests := []Test{
		{
			NewSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 0),
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 1. For second, 2. And so on.
				return 0, []uint64{run}, []uint64{10, 20}
			},
			Runs: 3,
			Result: deflakedCover{
				cover: cover.FromRaw([]uint64{10, 20}),
			},
		},
		{
			NewSignal: signal.FromRaw([]uint64{0, 1, 2}, 0),
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
			Result: deflakedCover{
				// Cover is a union of all coverages.
				cover: cover.FromRaw([]uint64{10, 20, 30, 40}),
				// 0, 2, 6 were in three resuls.
				stableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
				// 0, 2 were also in newSignal.
				newStableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
			},
		},
		{
			NewSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 3),
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 0 and 1. For second, 1 and 2. And so on.
				return 0, []uint64{run, run + 1}, []uint64{10, 20}
			},
			Runs: 2,
			Result: deflakedCover{
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{2}, 0),
				newStableSignal: signal.FromRaw([]uint64{2}, 0),
			},
		},
	}

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			testJob := &triageJob{
				p:         prog,
				newSignal: test.NewSignal,
			}

			var run uint64
			ret, stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
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
			}, newCover(), nil, false)

			assert.False(t, stop)
			assert.Equal(t, run, test.Runs)
			assert.ElementsMatch(t, ret.cover.Serialize(), test.Result.cover.Serialize())
			assert.ElementsMatch(t, ret.stableSignal.ToRaw(), test.Result.stableSignal.ToRaw())
			assert.ElementsMatch(t, ret.newStableSignal.ToRaw(), test.Result.newStableSignal.ToRaw())
		})
	}
}
