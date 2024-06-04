// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package runtest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	_ "github.com/google/syzkaller/sys/test/gen" // pull in the test target
	"github.com/stretchr/testify/assert"
)

var (
	// Can be used as:
	// go test -v -run=Test/64_fork ./pkg/runtest -filter=nonfailing
	// to select a subset of tests to run.
	flagFilter = flag.String("filter", "", "prefix to match test file names")
	flagDebug  = flag.Bool("debug", false, "include debug output from the executor")
	flagGDB    = flag.Bool("gdb", false, "run executor under gdb")
)

func TestUnit(t *testing.T) {
	switch runtime.GOOS {
	case targets.OpenBSD:
		t.Skipf("broken on %v", runtime.GOOS)
	}
	// Test only one target in short mode (each takes 5+ seconds to run).
	shortTarget := targets.Get(targets.TestOS, targets.TestArch64Fork)
	for _, sysTarget := range targets.List[targets.TestOS] {
		if testing.Short() && sysTarget != shortTarget {
			continue
		}
		sysTarget1 := targets.Get(sysTarget.OS, sysTarget.Arch)
		t.Run(sysTarget1.Arch, func(t *testing.T) {
			t.Parallel()
			test(t, sysTarget1)
		})
	}
}

func test(t *testing.T, sysTarget *targets.Target) {
	target, err := prog.GetTarget(sysTarget.OS, sysTarget.Arch)
	if err != nil {
		t.Fatal(err)
	}
	executor := csource.BuildExecutor(t, target, "../../", "-fsanitize-coverage=trace-pc")
	calls := make(map[*prog.Syscall]bool)
	for _, call := range target.Syscalls {
		calls[call] = true
	}
	enabledCalls := map[string]map[*prog.Syscall]bool{
		"":     calls,
		"none": calls,
	}
	ctx := &Context{
		Dir:          filepath.Join("..", "..", "sys", target.OS, targets.TestOS),
		Target:       target,
		Tests:        *flagFilter,
		Features:     0,
		EnabledCalls: enabledCalls,
		LogFunc: func(text string) {
			t.Helper()
			t.Logf(text)
		},
		Retries: 7, // empirical number that seem to reduce flakes to zero
		Verbose: true,
		Debug:   *flagDebug,
	}
	startRpcserver(t, target, executor, ctx)
	if err := ctx.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestCover(t *testing.T) {
	// End-to-end test for coverage/signal/comparisons collection.
	// We inject given blobs into KCOV buffer using syz_inject_cover,
	// and then test what we get back.
	t.Parallel()
	for _, arch := range []string{targets.TestArch32, targets.TestArch64, targets.TestArch64Fork} {
		sysTarget := targets.Get(targets.TestOS, arch)
		t.Run(arch, func(t *testing.T) {
			if sysTarget.BrokenCompiler != "" {
				t.Skipf("skipping due to broken compiler:\n%v", sysTarget.BrokenCompiler)
			}
			target, err := prog.GetTarget(targets.TestOS, arch)
			if err != nil {
				t.Fatal(err)
			}
			t.Parallel()
			testCover(t, target)
		})
	}
}

type CoverTest struct {
	Is64Bit int
	Input   []byte
	Flags   flatrpc.ExecFlag
	Cover   []uint64
	Signal  []uint64
	Comps   [][2]uint64
}

type Comparison struct {
	Type uint64
	Arg1 uint64
	Arg2 uint64
	PC   uint64
}

const (
	CmpConst = 1
	CmpSize1 = 0
	CmpSize2 = 2
	CmpSize4 = 4
	CmpSize8 = 6
)

func testCover(t *testing.T, target *prog.Target) {
	tests := []CoverTest{
		// Empty coverage.
		{
			Is64Bit: 1,
			Input:   makeCover64(),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		{
			Is64Bit: 0,
			Input:   makeCover32(),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		// Single 64-bit PC.
		{
			Is64Bit: 1,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0dec0dec0112233},
			Signal:  []uint64{0xc0dec0dec0112233},
		},
		// Single 32-bit PC.
		{
			Is64Bit: 0,
			Input:   makeCover32(0xc0112233),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0112233},
			Signal:  []uint64{0xc0112233},
		},
		// Ensure we don't sent cover/signal when not requested.
		{
			Is64Bit: 1,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0dec0dec0112233},
		},
		{
			Is64Bit: 1,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectSignal,
			Signal:  []uint64{0xc0dec0dec0112233},
		},
		// Coverage deduplication.
		{
			Is64Bit: 1,
			Input: makeCover64(0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011,
				0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033, 0xc0dec0dec0000011),
			Flags: flatrpc.ExecFlagCollectCover,
			Cover: []uint64{0xc0dec0dec0000011, 0xc0dec0dec0000033, 0xc0dec0dec0000022,
				0xc0dec0dec0000011, 0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033},
		},
		{
			Is64Bit: 1,
			Input: makeCover64(0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011,
				0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033, 0xc0dec0dec0000011),
			Flags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagDedupCover,
			Cover: []uint64{0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011},
		},
		// Signal hashing.
		{
			Is64Bit: 1,
			Input: makeCover64(0xc0dec0dec0011001, 0xc0dec0dec0022002, 0xc0dec0dec00330f0,
				0xc0dec0dec0044b00, 0xc0dec0dec0011001, 0xc0dec0dec0022002),
			Flags: flatrpc.ExecFlagCollectSignal,
			Signal: []uint64{0xc0dec0dec0011b01, 0xc0dec0dec0044bf0, 0xc0dec0dec00330f2,
				0xc0dec0dec0022003, 0xc0dec0dec0011001},
		},
		// Invalid non-kernel PCs must fail test execution.
		{
			Is64Bit: 1,
			Input:   makeCover64(0xc0dec0dec0000022, 0xc000000000000033),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		{
			Is64Bit: 0,
			Input:   makeCover32(0x33),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		// 64-bit comparisons.
		{
			Is64Bit: 1,
			Input: makeComps(
				// A normal 8-byte comparison must be returned in the output as is.
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 0},
				// Duplicate must be removed.
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 0},
				// Non-const comparisons must be duplicated both ways.
				Comparison{CmpSize8, 0x30, 0x31, 0},
				// Test sign-extension for smaller argument types.
				Comparison{CmpSize1 | CmpConst, 0xa3, 0x77, 0},
				Comparison{CmpSize1 | CmpConst, 0xff10, 0xffe1, 0},
				Comparison{CmpSize2 | CmpConst, 0xabcd, 0x4321, 0},
				Comparison{CmpSize4 | CmpConst, 0xabcd1234, 0x4321, 0},
				// Comparison with const 0 must be removed.
				Comparison{CmpSize8 | CmpConst, 0, 0x2222222222222222, 0},
				Comparison{CmpSize8, 0, 0x3333, 0},
				// Comparison of equal values must be removed.
				Comparison{CmpSize8, 0, 0, 0},
				Comparison{CmpSize8, 0x1111, 0x1111, 0},
				// Comparisons of kernel addresses must be removed.
				Comparison{CmpSize8 | CmpConst, 0xda1a0000, 0xda1a1000, 0},
				Comparison{CmpSize8, 0xda1a0000, 0, 0},
				Comparison{CmpSize8, 0, 0xda1a0010, 0},
				Comparison{CmpSize8 | CmpConst, 0xc0dec0dec0de0000, 0xc0dec0dec0de1000, 0},
				// But not with something that's not a kernel address.
				Comparison{CmpSize8 | CmpConst, 0xda1a0010, 0xabcd, 0},
			),
			Flags: flatrpc.ExecFlagCollectComps,
			Comps: [][2]uint64{
				{0x2222222222222222, 0x1111111111111111},
				{0x30, 0x31},
				{0x31, 0x30},
				{0x77, 0xffffffffffffffa3},
				{0xffffffffffffffe1, 0x10},
				{0x4321, 0xffffffffffffabcd},
				{0x4321, 0xffffffffabcd1234},
				{0x3333, 0},
				{0, 0x3333},
				{0xabcd, 0xda1a0010},
			},
		},
		// 32-bit comparisons must be the same, so test only a subset.
		{
			Is64Bit: 0,
			Input: makeComps(
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 0},
				Comparison{CmpSize2 | CmpConst, 0xabcd, 0x4321, 0},
				Comparison{CmpSize4 | CmpConst, 0xda1a0000, 0xda1a1000, 0},
				Comparison{CmpSize8 | CmpConst, 0xc0dec0dec0de0000, 0xc0dec0dec0de1000, 0},
				Comparison{CmpSize4 | CmpConst, 0xc0de0000, 0xc0de1000, 0},
				Comparison{CmpSize8 | CmpConst, 0xc0de0011, 0xc0de1022, 0},
			),
			Flags: flatrpc.ExecFlagCollectComps,
			Comps: [][2]uint64{
				{0x2222222222222222, 0x1111111111111111},
				{0x4321, 0xffffffffffffabcd},
				{0xc0dec0dec0de1000, 0xc0dec0dec0de0000},
			},
		},
		// TODO: test max signal filtering and cover filter when syz-executor handles them.
	}
	executor := csource.BuildExecutor(t, target, "../../")
	source := queue.Plain()
	startRpcserver(t, target, executor, source)
	for i, test := range tests {
		test := test
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			testCover1(t, target, test, source)
		})
	}
}

func testCover1(t *testing.T, target *prog.Target, test CoverTest, source *queue.PlainQueue) {
	text := fmt.Sprintf(`syz_inject_cover(0x%v, &AUTO="%s", AUTO)`, test.Is64Bit, hex.EncodeToString(test.Input))
	p, err := target.Deserialize([]byte(text), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	req := &queue.Request{
		Prog: p,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags:  flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone,
			ExecFlags: test.Flags,
		},
	}
	if test.Flags&flatrpc.ExecFlagCollectSignal != 0 {
		req.ReturnAllSignal = []int{0}
	}
	source.Submit(req)
	res := req.Wait(context.Background())
	if res.Err != nil || res.Info == nil || len(res.Info.Calls) != 1 || res.Info.Calls[0] == nil {
		t.Fatalf("program execution failed: status=%v err=%v\n%s", res.Status, res.Err, res.Output)
	}
	call := res.Info.Calls[0]
	var comps [][2]uint64
	for _, cmp := range call.Comps {
		comps = append(comps, [2]uint64{cmp.Op1, cmp.Op2})
	}
	if test.Cover == nil {
		test.Cover = []uint64{}
	}
	if test.Signal == nil {
		test.Signal = []uint64{}
	}
	assert.Equal(t, test.Cover, call.Cover)
	assert.Equal(t, test.Signal, call.Signal)
	// Comparisons are reordered and order does not matter, so compare without order.
	assert.ElementsMatch(t, test.Comps, comps)
}

func makeCover64(pcs ...uint64) []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.NativeEndian, uint64(len(pcs)))
	for _, pc := range pcs {
		binary.Write(w, binary.NativeEndian, pc)
	}
	return w.Bytes()
}

func makeCover32(pcs ...uint32) []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.NativeEndian, uint32(len(pcs)))
	for _, pc := range pcs {
		binary.Write(w, binary.NativeEndian, pc)
	}
	return w.Bytes()
}

func makeComps(comps ...Comparison) []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.NativeEndian, uint64(len(comps)))
	for _, cmp := range comps {
		binary.Write(w, binary.NativeEndian, cmp)
	}
	return w.Bytes()
}

func startRpcserver(t *testing.T, target *prog.Target, executor string, source queue.Source) {
	ctx, done := context.WithCancel(context.Background())
	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:   target,
				Debug:    *flagDebug,
				Features: flatrpc.FeatureSandboxNone,
				Sandbox:  flatrpc.ExecEnvSandboxNone,
			},
			Procs:    runtime.GOMAXPROCS(0),
			Slowdown: 10, // to deflake slower tests
		},
		Executor: executor,
		Dir:      t.TempDir(),
		Context:  ctx,
		GDB:      *flagGDB,
	}
	cfg.MachineChecked = func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
		cfg.Cover = true
		return source
	}
	errc := make(chan error)
	go func() {
		errc <- rpcserver.RunLocal(cfg)
	}()
	t.Cleanup(func() {
		done()
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	})
}

func TestParsing(t *testing.T) {
	t.Parallel()
	// Test only one target in race mode (we have gazillion of auto-generated Linux test).
	raceTarget := targets.Get(targets.TestOS, targets.TestArch64)
	for OS, arches := range targets.List {
		if testutil.RaceEnabled && OS != raceTarget.OS {
			continue
		}
		dir := filepath.Join("..", "..", "sys", OS, "test")
		if !osutil.IsExist(dir) {
			continue
		}
		files, err := progFileList(dir, "")
		if err != nil {
			t.Fatal(err)
		}
		for arch := range arches {
			if testutil.RaceEnabled && arch != raceTarget.Arch {
				continue
			}
			target, err := prog.GetTarget(OS, arch)
			if err != nil {
				t.Fatal(err)
			}
			sysTarget := targets.Get(target.OS, target.Arch)
			t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
				t.Parallel()
				for _, file := range files {
					p, requires, _, err := parseProg(target, dir, file)
					if err != nil {
						t.Errorf("failed to parse %v: %v", file, err)
					}
					if p == nil {
						continue
					}
					if runtime.GOOS != sysTarget.BuildOS {
						continue // we need at least preprocessor binary to generate sources
					}
					// syz_mount_image tests are very large and this test takes too long.
					// syz-imagegen that generates does some of this testing (Deserialize/SerializeForExec).
					if requires["manual"] {
						continue
					}
					if _, err = csource.Write(p, csource.ExecutorOpts); err != nil {
						t.Errorf("failed to generate C source for %v: %v", file, err)
					}
				}
			})
		}
	}
}

func TestRequires(t *testing.T) {
	{
		requires := parseRequires([]byte("# requires: manual arch=amd64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
	{
		requires := parseRequires([]byte("# requires: -arch=arm64 manual -arch=riscv64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
}
