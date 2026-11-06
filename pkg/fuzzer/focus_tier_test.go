// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFocusTiers(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	ctx := t.Context()
	const lowPC, highPC = 0x10010, 0x20020
	areas := []corpus.FocusArea{
		{Name: "low", CoverPCs: map[uint64]struct{}{lowPC: {}}, Weight: 3.0},
		{Name: "high", CoverPCs: map[uint64]struct{}{highPC: {}}, Weight: 6.0},
		{Name: "zero", CoverPCs: map[uint64]struct{}{0x30030: {}}, Weight: 0},
		{Weight: 1.0},
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:    corpus.NewFocusedCorpus(ctx, nil, areas),
		PatchTest: true,
		Coverage:  true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$res0"]: true,
		},
	}, rand.New(rand.NewSource(0)), target)

	// Tiers are sorted by weight, areas with zero weight are dropped, and the last tier
	// is the catch-all one.
	require.Len(t, fuzzer.tiers, 3)
	high, low, catchAll := fuzzer.tiers[0], fuzzer.tiers[1], fuzzer.tiers[2]
	assert.Equal(t, 6.0, high.weight)
	assert.Equal(t, 3.0, low.weight)
	assert.Equal(t, 1.0, catchAll.weight)
	assert.Nil(t, catchAll.coverPCs)
	assert.True(t, high.inFocus)
	assert.True(t, low.inFocus)
	assert.False(t, catchAll.inFocus)

	t.Run("triage_queue_by_signal", func(t *testing.T) {
		// Signal may be an edge that only matches the higher bits of the PC.
		edge := func(pc uint64) uint64 { return pc ^ 0x123 }
		assert.Same(t, high.triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
			0: {newSignal: signal.FromRaw([]uint64{edge(lowPC)}, 1)},
			1: {newSignal: signal.FromRaw([]uint64{edge(highPC)}, 1)},
		}))
		assert.Same(t, low.triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
			0: {newSignal: signal.FromRaw([]uint64{edge(lowPC)}, 1)},
		}))
		assert.Same(t, catchAll.triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
			0: {newSignal: signal.FromRaw([]uint64{0x99999}, 1)},
		}))
	})
	t.Run("tier_by_cover", func(t *testing.T) {
		// Cover PCs are matched exactly.
		assert.Same(t, high, fuzzer.tierForCall(&triageCall{cover: cover.FromRaw([]uint64{lowPC, highPC})}))
		assert.Same(t, low, fuzzer.tierForCall(&triageCall{cover: cover.FromRaw([]uint64{lowPC})}))
		assert.Same(t, catchAll, fuzzer.tierForCall(&triageCall{cover: cover.FromRaw([]uint64{lowPC ^ 0x123})}))
	})
	t.Run("triage_order", func(t *testing.T) {
		// Triage queues are drained strictly in the decreasing weight order.
		reqCatchAll, reqLow, reqHigh := &queue.Request{}, &queue.Request{}, &queue.Request{}
		catchAll.triageQueue.Append().Submit(reqCatchAll)
		low.triageQueue.Append().Submit(reqLow)
		high.triageQueue.Append().Submit(reqHigh)
		assert.Same(t, reqHigh, fuzzer.Next())
		assert.Same(t, reqLow, fuzzer.Next())
		assert.Same(t, reqCatchAll, fuzzer.Next())
	})
	t.Run("smash_shares", func(t *testing.T) {
		// Smash queues are served proportionally to the tier weights.
		const iters = 2000
		tierReqs := make(map[*queue.Request]int)
		for i, tier := range fuzzer.tiers {
			for range iters {
				req := &queue.Request{}
				tier.smashQueue.Submit(req)
				tierReqs[req] = i
			}
		}
		served := make([]int, len(fuzzer.tiers))
		for range iters {
			if i, ok := tierReqs[fuzzer.Next()]; ok {
				served[i]++
			}
		}
		// Hints queues are empty, so smash queues (total weight smashShare * 10) compete
		// only with new fuzzing (weight 1.0 * 10 in the patch testing mode).
		total := float64(iters) * smashShare / (smashShare + 1.0)
		assert.InDelta(t, total*0.6, served[0], iters*0.05)
		assert.InDelta(t, total*0.3, served[1], iters*0.05)
		assert.InDelta(t, total*0.1, served[2], iters*0.05)
	})
}
