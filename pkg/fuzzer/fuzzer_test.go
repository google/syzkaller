// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"math/rand"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/execbackend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFuzz(t *testing.T) {
	t.Cleanup(checkGoroutineLeaks)

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..", "-fsanitize-coverage=trace-pc", "-g")
	var pcs []uint64
	t.Run("normal", func(t *testing.T) {
		pcs = testFuzz(t, target, executor, false, nil)
	})
	t.Run("patch_test", func(t *testing.T) {
		testFuzz(t, target, executor, true, []corpus.FocusArea{
			{Name: "high", CoverPCs: map[uint64]struct{}{pcs[0]: {}}, Weight: 6.0},
			{Name: "low", CoverPCs: map[uint64]struct{}{pcs[len(pcs)-1]: {}}, Weight: 3.0},
			{Weight: 1.0},
		})
	})
}

func testFuzz(t *testing.T, target *prog.Target, executor string, patchTest bool, areas []corpus.FocusArea) []uint64 {
	ctx := t.Context()

	corpusUpdates := make(chan corpus.NewItemEvent)
	fuzzer := NewFuzzer(ctx, &Config{
		Debug:     true,
		Corpus:    corpus.NewFocusedCorpus(ctx, corpusUpdates, areas),
		PatchTest: patchTest,
		Logf: func(level int, msg string, args ...any) {
			if level > 1 {
				return
			}
			t.Logf(msg, args...)
		},
		Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["syz_test_fuzzer1"]: true,
		},
	}, rand.New(testutil.RandSource(t)), target)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case u := <-corpusUpdates:
				t.Logf("new prog:\n%s", u.ProgData)
			}
		}
	}()

	tf := &testFuzzer{
		t:         t,
		target:    target,
		fuzzer:    fuzzer,
		executor:  executor,
		iterLimit: 10000,
		expectedCrashes: map[string]bool{
			"first bug":  true,
			"second bug": true,
		},
	}
	tf.run()

	t.Logf("resulting corpus:")
	for _, p := range fuzzer.Config.Corpus.Programs() {
		t.Logf("-----")
		t.Logf("%s", p.Serialize())
	}
	return fuzzer.Config.Corpus.Cover()
}

func TestFocusTiers(t *testing.T) {
	t.Cleanup(checkGoroutineLeaks)

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	ctx := t.Context()
	areas := []corpus.FocusArea{
		{Name: "low", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 3.0},
		{Name: "high", CoverPCs: map[uint64]struct{}{20: {}}, Weight: 6.0},
		{Name: "zero", CoverPCs: map[uint64]struct{}{30: {}}, Weight: 0},
		{Weight: 1.0},
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:    corpus.NewFocusedCorpus(ctx, nil, areas),
		PatchTest: true,
		Coverage:  true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$res0"]: true,
			target.SyscallMap["test$int"]:  true,
		},
	}, rand.New(rand.NewSource(0)), target)

	require.Len(t, fuzzer.tiers, 3)
	assert.Equal(t, 6.0, fuzzer.tiers[0].weight)
	assert.True(t, fuzzer.tiers[0].inFocus)
	assert.Equal(t, 3.0, fuzzer.tiers[1].weight)
	assert.True(t, fuzzer.tiers[1].inFocus)
	assert.Equal(t, 1.0, fuzzer.tiers[2].weight)
	assert.False(t, fuzzer.tiers[2].inFocus)

	// Verify triageQueueForCalls routes to the highest-weight matching tier.
	assert.Same(t, fuzzer.tiers[0].triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
		0: {newSignal: signal.FromRaw([]uint64{10}, 1)},
		1: {newSignal: signal.FromRaw([]uint64{20}, 1)},
	}))
	assert.Same(t, fuzzer.tiers[1].triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
		0: {newSignal: signal.FromRaw([]uint64{10}, 1)},
	}))
	assert.Same(t, fuzzer.tiers[2].triageQueue, fuzzer.triageQueueForCalls(map[int]*triageCall{
		0: {newSignal: signal.FromRaw([]uint64{99}, 1)},
	}))

	// Verify tierForCall routes to the highest-weight matching tier.
	var bothCover, lowCover, otherCover cover.Cover
	bothCover.Merge([]uint64{10, 20})
	lowCover.Merge([]uint64{10})
	otherCover.Merge([]uint64{99})
	assert.Same(t, &fuzzer.tiers[0], fuzzer.tierForCall(&triageCall{cover: bothCover}))
	assert.Same(t, &fuzzer.tiers[1], fuzzer.tierForCall(&triageCall{cover: lowCover}))
	assert.Same(t, &fuzzer.tiers[2], fuzzer.tierForCall(&triageCall{cover: otherCover}))

	// Verify triage queues are drained strictly in decreasing weight order.
	reqCatchAll, reqLow, reqHigh := &queue.Request{}, &queue.Request{}, &queue.Request{}
	fuzzer.tiers[2].triageQueue.Append().Submit(reqCatchAll)
	fuzzer.tiers[1].triageQueue.Append().Submit(reqLow)
	fuzzer.tiers[0].triageQueue.Append().Submit(reqHigh)
	assert.Same(t, reqHigh, fuzzer.Next())
	assert.Same(t, reqLow, fuzzer.Next())
	assert.Same(t, reqCatchAll, fuzzer.Next())

	// Verify smashQueue and hintsQueue are separate per-tier queues and both are served
	// without hintsQueue starving smashQueue.
	for i := range fuzzer.tiers {
		require.NotNil(t, fuzzer.tiers[i].smashQueue)
		require.NotNil(t, fuzzer.tiers[i].hintsQueue)
		assert.NotSame(t, fuzzer.tiers[i].smashQueue, fuzzer.tiers[i].hintsQueue)
	}
	smashReqs := make(map[*queue.Request]bool)
	hintsReqs := make(map[*queue.Request]bool)
	for range 20 {
		sReq := &queue.Request{Type: flatrpc.RequestTypeProgram}
		hReq := &queue.Request{Type: flatrpc.RequestTypeProgram}
		smashReqs[sReq] = true
		hintsReqs[hReq] = true
		fuzzer.tiers[0].smashQueue.Submit(sReq)
		fuzzer.tiers[0].hintsQueue.Submit(hReq)
	}
	smashServed, hintsServed := 0, 0
	for range 40 {
		req := fuzzer.Next()
		if smashReqs[req] {
			smashServed++
		} else if hintsReqs[req] {
			hintsServed++
		}
	}
	assert.Positive(t, smashServed, "smashQueue must be served")
	assert.Positive(t, hintsServed, "hintsQueue must be served")

	// Verify ChoiceTable regenerates when transitioning from many unfocused programs
	// to a smaller set of focused programs.
	ct := fuzzer.ChoiceTable()
	for i := range 20 {
		p := target.Generate(rand.NewSource(int64(i)), 3, ct)
		fuzzer.Config.Corpus.Save(corpus.NewInput{
			Prog:   p,
			Call:   0,
			Signal: signal.FromRaw([]uint64{uint64(100 + i)}, 0),
			Cover:  []uint64{uint64(100 + i)},
		})
	}
	fuzzer.updateChoiceTable()
	assert.Greater(t, fuzzer.ctProgs, 5)

	focusedProg := target.Generate(rand.NewSource(999), 2, ct)
	fuzzer.Config.Corpus.Save(corpus.NewInput{
		Prog:   focusedProg,
		Call:   0,
		Signal: signal.FromRaw([]uint64{20}, 0),
		Cover:  []uint64{20},
	})
	require.Len(t, fuzzer.Config.Corpus.FocusedPrograms(), 1)
	assert.Eventually(t, func() bool {
		fuzzer.ChoiceTable()
		fuzzer.ctMu.RLock()
		defer fuzzer.ctMu.RUnlock()
		return fuzzer.ctProgs == 1 && len(fuzzer.ctRelated) >= 1
	}, time.Second, 5*time.Millisecond)

	tj := &triageJob{fuzzer: fuzzer}
	assert.True(t, tj.shouldStartHints(), "should start hints when backlog is small")
	fuzzer.statJobsHints.Add(30)
	assert.False(t, tj.shouldStartHints(), "should cap hints when backlog >= 30 in PatchTest mode")
	fuzzer.statJobsHints.Add(-30)
}

func BenchmarkFuzzer(b *testing.B) {
	b.ReportAllocs()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		b.Fatal(err)
	}
	ctx := b.Context()
	calls := map[*prog.Syscall]bool{}
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		Coverage:     true,
		EnabledCalls: calls,
	}, rand.New(rand.NewSource(time.Now().UnixNano())), target)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := fuzzer.Next()
			res, _, _ := emulateExec(req)
			req.Done(res)
		}
	})
}

// Based on the example from Go documentation.
var crc32q = crc32.MakeTable(0xD5828281)

func emulateExec(req *queue.Request) (*queue.Result, string, error) {
	serializedLines := bytes.Split(req.Prog.Serialize(), []byte("\n"))
	var info flatrpc.ProgInfo
	for i, call := range req.Prog.Calls {
		cover := []uint64{uint64(call.Meta.ID*1024) +
			uint64(crc32.Checksum(serializedLines[i], crc32q)%4)}
		callInfo := &flatrpc.CallInfo{}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0 {
			callInfo.Cover = cover
		}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 {
			callInfo.Signal = cover
		}
		info.Calls = append(info.Calls, callInfo)
	}
	return &queue.Result{Info: &info}, "", nil
}

type testFuzzer struct {
	t               testing.TB
	target          *prog.Target
	fuzzer          *Fuzzer
	executor        string
	mu              sync.Mutex
	crashes         map[string]int
	expectedCrashes map[string]bool
	iter            int
	iterLimit       int
	done            func()
	finished        atomic.Bool
}

func (f *testFuzzer) run() {
	f.crashes = make(map[string]int)
	ctx, done := context.WithCancel(context.Background())
	f.done = done

	cfg := execbackend.LocalConfig{
		Target:      f.target,
		ExecutorBin: f.executor,
		Dir:         f.t.TempDir(),
		Source:      f,
	}

	reps, err := execbackend.RunLocal(ctx, cfg)
	if err != nil && err != context.Canceled {
		f.t.Fatal(err)
	}
	if len(reps) > 0 {
		f.t.Logf("crash: %s\noutput:\n%s", reps[0].Title, reps[0].Output)
	}

	assert.Equal(f.t, len(f.expectedCrashes), len(f.crashes), "not all expected crashes were found")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatProgs.Val(), "must have non-empty corpus")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatSignal.Val(), "must have non-empty signal")
}

func (f *testFuzzer) Next() *queue.Request {
	if f.finished.Load() {
		return nil
	}
	req := f.fuzzer.Next()
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone
	req.ReturnOutput = true
	req.ReturnError = true
	req.OnDone(f.OnDone)
	return req
}

func (f *testFuzzer) OnDone(req *queue.Request, res *queue.Result) bool {
	// TODO: support hints emulation.
	match := crashRe.FindSubmatch(res.Output)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finished.Load() {
		// Don't touch f.crashes in this case b/c it can cause races with the main goroutine,
		// and logging can cause "Log in goroutine after TestFuzz has completed" panic.
		return true
	}
	if match != nil {
		crash := string(match[1])
		f.t.Logf("CRASH: %s", crash)
		res.Status = queue.Crashed
		if !f.expectedCrashes[crash] {
			f.t.Errorf("unexpected crash: %q", crash)
		}
		f.crashes[crash]++
	}
	f.iter++
	corpusProgs := f.fuzzer.Config.Corpus.StatProgs.Val()
	signal := f.fuzzer.Config.Corpus.StatSignal.Val()
	if f.iter%100 == 0 {
		f.t.Logf("<iter %d>: corpus %d, signal %d, max signal %d, crash types %d, running jobs %d",
			f.iter, corpusProgs, signal, len(f.fuzzer.Cover.maxSignal),
			len(f.crashes), f.fuzzer.statJobs.Val())
	}
	criteriaMet := len(f.crashes) == len(f.expectedCrashes) &&
		corpusProgs > 0 && signal > 0
	if f.iter > f.iterLimit || criteriaMet {
		f.done()
		f.finished.Store(true)
	}
	return true
}

var crashRe = regexp.MustCompile(`{{CRASH: (.*?)}}`)

func checkGoroutineLeaks() {
	// Inspired by src/net/http/main_test.go.
	buf := make([]byte, 2<<20)
	err := ""
	for range 3 {
		buf = buf[:runtime.Stack(buf, true)]
		err = ""
		for g := range strings.SplitSeq(string(buf), "\n\n") {
			if !strings.Contains(g, "pkg/fuzzer/fuzzer.go") {
				continue
			}
			err = fmt.Sprintf("%sLeaked goroutine:\n%s", err, g)
		}
		if err == "" {
			return
		}
		// Give ctx.Done() a chance to propagate to all goroutines.
		time.Sleep(100 * time.Millisecond)
	}
	if err != "" {
		panic(err)
	}
}
