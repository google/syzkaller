// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestDeflakeFail(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	testJob := &triageJob{
		p:         prog,
		info:      &flatrpc.CallInfo{},
		newSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 0),
	}

	run := 0
	ret, stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		run++
		// For first, we return 0. For second, 2. And so on.
		return fakeResult(0, []uint64{uint64(run)}, []uint64{10, 20})
	}, newCover(), nil, false)
	assert.False(t, stop)
	assert.Equal(t, 3, run)
	assert.Empty(t, ret.stableSignal.ToRaw())
	assert.Empty(t, ret.newStableSignal.ToRaw())
}

func TestDeflakeSuccess1(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	testJob := &triageJob{
		p:         prog,
		info:      &flatrpc.CallInfo{},
		newSignal: signal.FromRaw([]uint64{0, 1, 2}, 0),
	}
	run := 0
	ret, stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		run++
		switch run {
		case 1:
			return fakeResult(0, []uint64{0, 2, 4, 6, 8}, []uint64{10, 20})
		case 2:
			// This one should be ignored -- it has a different errno.
			return fakeResult(1, []uint64{0, 1, 2}, []uint64{100})
		case 3:
			return fakeResult(0, []uint64{0, 2, 4, 6, 8}, []uint64{20, 30})
		case 4:
			return fakeResult(0, []uint64{0, 2, 6}, []uint64{30, 40})
		}
		// We expect it to have finished earlier.
		t.Fatal("only 4 runs were expected")
		return nil
	}, newCover(), nil, false)
	assert.False(t, stop)
	assert.Equal(t, run, 4)
	// Cover is a union of all coverages.
	assert.ElementsMatch(t, []uint64{10, 20, 30, 40}, ret.cover.Serialize())
	// 0, 2, 6 were in three resuls.
	assert.ElementsMatch(t, []uint64{0, 2, 6}, ret.stableSignal.ToRaw())
	// 0, 2 were also in newSignal.
	assert.ElementsMatch(t, []uint64{0, 2, 6}, ret.newStableSignal.ToRaw())
}

func TestDeflakeSuccess2(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	testJob := &triageJob{
		p:         prog,
		info:      &flatrpc.CallInfo{},
		newSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 3),
	}

	run := 0
	ret, stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		run++
		// For first, we return 0 and 1. For second, 1 and 2. And so on.
		return fakeResult(0, []uint64{uint64(run), uint64(run + 1)}, []uint64{10, 20})
	}, newCover(), nil, false)
	assert.False(t, stop)
	assert.Equal(t, 2, run)
	assert.ElementsMatch(t, []uint64{10, 20}, ret.cover.Serialize())
	assert.ElementsMatch(t, []uint64{2}, ret.stableSignal.ToRaw())
	assert.ElementsMatch(t, []uint64{2}, ret.newStableSignal.ToRaw())
}

func fakeResult(errno int32, signal, cover []uint64) *queue.Result {
	return &queue.Result{
		Info: &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{
				{
					Error:  errno,
					Signal: signal,
					Cover:  cover,
				},
			},
		},
	}
}
