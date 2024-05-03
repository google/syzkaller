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
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestFuzz(t *testing.T) {
	defer checkGoroutineLeaks()

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..", "-fsanitize-coverage=trace-pc", "-g")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	corpusUpdates := make(chan corpus.NewItemEvent)
	fuzzer := NewFuzzer(ctx, &Config{
		Debug:  true,
		Corpus: corpus.NewMonitoredCorpus(ctx, corpusUpdates),
		Logf: func(level int, msg string, args ...interface{}) {
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

	tf := newTestFuzzer(t, fuzzer, map[string]bool{
		"first bug":  true,
		"second bug": true,
	}, 10000)

	for i := 0; i < 2; i++ {
		tf.registerExecutor(newProc(t, target, executor))
	}
	tf.wait()

	t.Logf("resulting corpus:")
	for _, p := range fuzzer.Config.Corpus.Programs() {
		t.Logf("-----")
		t.Logf("%s", p.Serialize())
	}

	assert.Equal(t, len(tf.expectedCrashes), len(tf.crashes),
		"not all expected crashes were found")
}

func BenchmarkFuzzer(b *testing.B) {
	b.ReportAllocs()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

const anyTestProg = `syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void}, AUTO)`

func TestRotate(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	corpusObj := corpus.NewCorpus(ctx)
	fuzzer := NewFuzzer(ctx, &Config{
		Debug:    true,
		Corpus:   corpusObj,
		Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["syz_compare"]: true,
		},
	}, rand.New(testutil.RandSource(t)), target)

	fakeSignal := func(size int) signal.Signal {
		var pc []uint32
		for i := 0; i < size; i++ {
			pc = append(pc, uint32(i))
		}
		return signal.FromRaw(pc, 0)
	}

	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)
	corpusObj.Save(corpus.NewInput{
		Prog:   prog,
		Call:   0,
		Signal: fakeSignal(100),
	})
	fuzzer.Cover.AddMaxSignal(fakeSignal(1000))

	assert.Equal(t, 1000, len(fuzzer.Cover.maxSignal))
	assert.Equal(t, 100, corpusObj.StatSignal.Val())

	// Rotate some of the signal.
	fuzzer.RotateMaxSignal(200)
	assert.Equal(t, 800, len(fuzzer.Cover.maxSignal))
	assert.Equal(t, 100, corpusObj.StatSignal.Val())

	plus, minus := fuzzer.Cover.GrabSignalDelta()
	assert.Equal(t, 0, plus.Len())
	assert.Equal(t, 200, minus.Len())

	// Rotate the rest.
	fuzzer.RotateMaxSignal(1000)
	assert.Equal(t, 100, len(fuzzer.Cover.maxSignal))
	assert.Equal(t, 100, corpusObj.StatSignal.Val())
	plus, minus = fuzzer.Cover.GrabSignalDelta()
	assert.Equal(t, 0, plus.Len())
	assert.Equal(t, 700, minus.Len())
}

// Based on the example from Go documentation.
var crc32q = crc32.MakeTable(0xD5828281)

func emulateExec(req *queue.Request) (*queue.Result, string, error) {
	serializedLines := bytes.Split(req.Prog.Serialize(), []byte("\n"))
	var info ipc.ProgInfo
	for i, call := range req.Prog.Calls {
		cover := uint32(call.Meta.ID*1024) +
			crc32.Checksum(serializedLines[i], crc32q)%4
		callInfo := ipc.CallInfo{}
		if req.NeedCover {
			callInfo.Cover = []uint32{cover}
		}
		if req.NeedSignal != queue.NoSignal {
			callInfo.Signal = []uint32{cover}
		}
		info.Calls = append(info.Calls, callInfo)
	}
	return &queue.Result{Info: &info}, "", nil
}

type testFuzzer struct {
	t               testing.TB
	eg              errgroup.Group
	fuzzer          *Fuzzer
	mu              sync.Mutex
	crashes         map[string]int
	expectedCrashes map[string]bool
	iter            int
	iterLimit       int
}

func newTestFuzzer(t testing.TB, fuzzer *Fuzzer, expectedCrashes map[string]bool, iterLimit int) *testFuzzer {
	return &testFuzzer{
		t:               t,
		fuzzer:          fuzzer,
		expectedCrashes: expectedCrashes,
		crashes:         map[string]int{},
		iterLimit:       iterLimit,
	}
}

func (f *testFuzzer) oneMore() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.iter++
	if f.iter%100 == 0 {
		f.t.Logf("<iter %d>: corpus %d, signal %d, max signal %d, crash types %d, running jobs %d",
			f.iter, f.fuzzer.Config.Corpus.StatProgs.Val(), f.fuzzer.Config.Corpus.StatSignal.Val(),
			len(f.fuzzer.Cover.maxSignal), len(f.crashes), f.fuzzer.statJobs.Val())
	}
	return f.iter < f.iterLimit &&
		(f.expectedCrashes == nil || len(f.crashes) != len(f.expectedCrashes))
}

func (f *testFuzzer) registerExecutor(proc *executorProc) {
	f.eg.Go(func() error {
		for f.oneMore() {
			req := f.fuzzer.Next()
			res, crash, err := proc.execute(req)
			if err != nil {
				return err
			}
			if crash != "" {
				res = &queue.Result{Status: queue.Crashed}
				if !f.expectedCrashes[crash] {
					return fmt.Errorf("unexpected crash: %q", crash)
				}
				f.mu.Lock()
				f.t.Logf("CRASH: %s", crash)
				f.crashes[crash]++
				f.mu.Unlock()
			}
			req.Done(res)
		}
		return nil
	})
}

func (f *testFuzzer) wait() {
	t := f.t
	err := f.eg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("crashes:")
	for title, cnt := range f.crashes {
		t.Logf("%s: %d", title, cnt)
	}
}

// TODO: it's already implemented in syz-fuzzer/proc.go,
// pkg/runtest and tools/syz-execprog.
// Looks like it's time to factor out this functionality.
type executorProc struct {
	env      *ipc.Env
	execOpts ipc.ExecOpts
}

func newProc(t *testing.T, target *prog.Target, executor string) *executorProc {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	config.Executor = executor
	execOpts.EnvFlags |= ipc.FlagSignal
	env, err := ipc.MakeEnv(config, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.Close() })
	return &executorProc{
		env:      env,
		execOpts: *execOpts,
	}
}

var crashRe = regexp.MustCompile(`{{CRASH: (.*?)}}`)

func (proc *executorProc) execute(req *queue.Request) (*queue.Result, string, error) {
	execOpts := proc.execOpts
	// TODO: it's duplicated from fuzzer.go.
	if req.NeedSignal != queue.NoSignal {
		execOpts.ExecFlags |= ipc.FlagCollectSignal
	}
	if req.NeedCover {
		execOpts.ExecFlags |= ipc.FlagCollectCover
	}
	// TODO: support req.NeedHints.
	output, info, _, err := proc.env.Exec(&execOpts, req.Prog)
	ret := crashRe.FindStringSubmatch(string(output))
	if ret != nil {
		return nil, ret[1], nil
	} else if err != nil {
		return nil, "", err
	}
	return &queue.Result{Info: info}, "", nil
}

func checkGoroutineLeaks() {
	// Inspired by src/net/http/main_test.go.
	buf := make([]byte, 2<<20)
	err := ""
	for i := 0; i < 3; i++ {
		buf = buf[:runtime.Stack(buf, true)]
		err = ""
		for _, g := range strings.Split(string(buf), "\n\n") {
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
