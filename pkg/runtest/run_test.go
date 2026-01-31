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
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
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
			t.Log(text)
		},
		Retries: 7, // empirical number that seem to reduce flakes to zero
		Verbose: true,
		Debug:   *flagDebug,
	}
	ctx.Init()
	waitCtx := startRPCServer(t, target, executor, ctx, rpcParams{
		manyProcs: true,
		machineChecked: func(features flatrpc.Feature) {
			// Features we expect to be enabled on the test OS.
			// All sandboxes except for none are not implemented, coverage is not returned,
			// and setup for few features is failing specifically to test feature detection.
			want := flatrpc.FeatureCoverage |
				flatrpc.FeatureExtraCoverage |
				flatrpc.FeatureDelayKcovMmap |
				flatrpc.FeatureKcovResetIoctl |
				flatrpc.FeatureSandboxNone |
				flatrpc.FeatureFault |
				flatrpc.FeatureNetDevices |
				flatrpc.FeatureKCSAN |
				flatrpc.FeatureNicVF |
				flatrpc.FeatureUSBEmulation |
				flatrpc.FeatureVhciInjection |
				flatrpc.FeatureWifiEmulation |
				flatrpc.FeatureLRWPANEmulation |
				flatrpc.FeatureBinFmtMisc |
				flatrpc.FeatureSwap |
				flatrpc.FeatureMemoryDump
			for feat, name := range flatrpc.EnumNamesFeature {
				if features&feat != want&feat {
					t.Errorf("expect feature %v to be %v, but it is %v",
						name, want&feat != 0, features&feat != 0)
				}
			}
		},
	})
	if t.Failed() {
		return
	}
	if err := ctx.Run(waitCtx); err != nil {
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
	Is64Bit         bool
	ExtraCoverage   bool
	Input           []byte
	MaxSignal       []uint64
	CoverFilter     []uint64
	ReturnAllSignal bool
	Flags           flatrpc.ExecFlag
	Cover           []uint64
	Signal          []uint64
	Comps           []*flatrpc.Comparison
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
			Is64Bit: true,
			Input:   makeCover64(),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		{
			Is64Bit: false,
			Input:   makeCover32(),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		// Single 64-bit PC.
		{
			Is64Bit: true,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0dec0dec0112233},
			Signal:  []uint64{0xc0dec0dec0112233},
		},
		// Single 32-bit PC.
		{
			Is64Bit: false,
			Input:   makeCover32(0xc0112233),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0112233},
			Signal:  []uint64{0xc0112233},
		},
		// Ensure we don't sent cover/signal when not requested.
		{
			Is64Bit: true,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectCover,
			Cover:   []uint64{0xc0dec0dec0112233},
		},
		{
			Is64Bit: true,
			Input:   makeCover64(0xc0dec0dec0112233),
			Flags:   flatrpc.ExecFlagCollectSignal,
			Signal:  []uint64{0xc0dec0dec0112233},
		},
		// Coverage deduplication.
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011,
				0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033, 0xc0dec0dec0000011),
			Flags: flatrpc.ExecFlagCollectCover,
			Cover: []uint64{0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011,
				0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033, 0xc0dec0dec0000011},
		},
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0000033, 0xc0dec0dec0000022, 0xc0dec0dec0000011,
				0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033, 0xc0dec0dec0000011),
			Flags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagDedupCover,
			Cover: []uint64{0xc0dec0dec0000011, 0xc0dec0dec0000022, 0xc0dec0dec0000033},
		},
		// Signal hashing.
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0011001, 0xc0dec0dec0022002, 0xc0dec0dec00330f0,
				0xc0dec0dec0044b00, 0xc0dec0dec0011001, 0xc0dec0dec0022002),
			Flags: flatrpc.ExecFlagCollectSignal,
			Signal: []uint64{0xc0dec0dec0011b01, 0xc0dec0dec0044bf0, 0xc0dec0dec00330f2,
				0xc0dec0dec0022003, 0xc0dec0dec0011001},
		},
		// Invalid non-kernel PCs must fail test execution.
		{
			Is64Bit: true,
			Input:   makeCover64(0xc0dec0dec0000022, 0xc000000000000033),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		{
			Is64Bit: false,
			Input:   makeCover32(0x33),
			Flags:   flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
		},
		// 64-bit comparisons.
		{
			Is64Bit: true,
			Input: makeComps(
				// A normal 8-byte comparison must be returned in the output as is.
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 1},
				// Duplicate must be removed.
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 1},
				// Non-const comparisons must be duplicated both ways.
				Comparison{CmpSize8, 0x30, 0x31, 1},
				// Test sign-extension for smaller argument types.
				Comparison{CmpSize1 | CmpConst, 0xa3, 0x77, 1},
				Comparison{CmpSize1 | CmpConst, 0xff10, 0xffe1, 1},
				Comparison{CmpSize2 | CmpConst, 0xabcd, 0x4321, 1},
				Comparison{CmpSize4 | CmpConst, 0xabcd1234, 0x4321, 1},
				// Comparison with const 0 must be removed.
				Comparison{CmpSize8 | CmpConst, 0, 0x2222222222222222, 1},
				Comparison{CmpSize8, 0, 0x3333, 1},
				// Comparison of equal values must be removed.
				Comparison{CmpSize8, 0, 0, 1},
				Comparison{CmpSize8, 0x1111, 0x1111, 1},
				// Comparisons of kernel addresses must be removed.
				Comparison{CmpSize8 | CmpConst, 0xda1a0000, 0xda1a1000, 1},
				Comparison{CmpSize8, 0xda1a0000, 0, 1},
				Comparison{CmpSize8, 0, 0xda1a0010, 1},
				Comparison{CmpSize8 | CmpConst, 0xc0dec0dec0de0000, 0xc0dec0dec0de1000, 1},
				// But not with something that's not a kernel address.
				Comparison{CmpSize8 | CmpConst, 0xda1a0010, 0xabcd, 1},
			),
			Flags: flatrpc.ExecFlagCollectComps,
			Comps: []*flatrpc.Comparison{
				{Pc: 1, Op1: 0x2222222222222222, Op2: 0x1111111111111111, IsConst: true},
				{Pc: 1, Op1: 0x31, Op2: 0x30, IsConst: false},
				{Pc: 1, Op1: 0x77, Op2: 0xffffffffffffffa3, IsConst: true},
				{Pc: 1, Op1: 0xffffffffffffffe1, Op2: 0x10, IsConst: true},
				{Pc: 1, Op1: 0x4321, Op2: 0xffffffffffffabcd, IsConst: true},
				{Pc: 1, Op1: 0x4321, Op2: 0xffffffffabcd1234, IsConst: true},
				{Pc: 1, Op1: 0x3333, Op2: 0, IsConst: false},
				{Pc: 1, Op1: 0xabcd, Op2: 0xda1a0010, IsConst: true},
			},
		},
		// 32-bit comparisons must be the same, so test only a subset.
		{
			Is64Bit: false,
			Input: makeComps(
				Comparison{CmpSize8 | CmpConst, 0x1111111111111111, 0x2222222222222222, 1},
				Comparison{CmpSize2 | CmpConst, 0xabcd, 0x4321, 2},
				Comparison{CmpSize4 | CmpConst, 0xda1a0000, 0xda1a1000, 1},
				Comparison{CmpSize8 | CmpConst, 0xc0dec0dec0de0000, 0xc0dec0dec0de1000, 3},
				Comparison{CmpSize4 | CmpConst, 0xc0de0000, 0xc0de1000, 1},
				Comparison{CmpSize4 | CmpConst, 0xc0de0011, 0xc0de1022, 1},
			),
			Flags: flatrpc.ExecFlagCollectComps,
			Comps: []*flatrpc.Comparison{
				{Pc: 1, Op1: 0x2222222222222222, Op2: 0x1111111111111111, IsConst: true},
				{Pc: 2, Op1: 0x4321, Op2: 0xffffffffffffabcd, IsConst: true},
				{Pc: 3, Op1: 0xc0dec0dec0de1000, Op2: 0xc0dec0dec0de0000, IsConst: true},
			},
		},
		// Test max signal.
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0000001, 0xc0dec0dec0000010, 0xc0dec0dec0000002,
				0xc0dec0dec0000100, 0xc0dec0dec0001000),
			MaxSignal: []uint64{0xc0dec0dec0000001, 0xc0dec0dec0000013, 0xc0dec0dec0000abc},
			Flags:     flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover: []uint64{0xc0dec0dec0000001, 0xc0dec0dec0000010, 0xc0dec0dec0000002,
				0xc0dec0dec0000100, 0xc0dec0dec0001000},
			Signal: []uint64{0xc0dec0dec0001100, 0xc0dec0dec0000102},
		},
		{
			Is64Bit:   false,
			Input:     makeCover32(0xc0000001, 0xc0000010, 0xc0000002, 0xc0000100, 0xc0001000),
			MaxSignal: []uint64{0xc0000001, 0xc0000013, 0xc0000abc},
			Flags:     flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:     []uint64{0xc0000001, 0xc0000010, 0xc0000002, 0xc0000100, 0xc0001000},
			Signal:    []uint64{0xc0001100, 0xc0000102},
		},
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0000001, 0xc0dec0dec0000010, 0xc0dec0dec0000002,
				0xc0dec0dec0000100, 0xc0dec0dec0001000),
			MaxSignal:       []uint64{0xc0dec0dec0000001, 0xc0dec0dec0000013, 0xc0dec0dec0000abc},
			ReturnAllSignal: true,
			Flags:           flatrpc.ExecFlagCollectSignal,
			Signal: []uint64{0xc0dec0dec0001100, 0xc0dec0dec0000102, 0xc0dec0dec0000012,
				0xc0dec0dec0000011, 0xc0dec0dec0000001},
		},
		// Test cover filter.
		{
			Is64Bit: true,
			Input: makeCover64(0xc0dec0dec0000001, 0xc0dec0dec0000010, 0xc0dec0dec0000020,
				0xc0dec0dec0000040, 0xc0dec0dec0000100, 0xc0dec0dec0001000, 0xc0dec0dec0002000),
			CoverFilter: []uint64{0xc0dec0dec0000002, 0xc0dec0dec0000100},
			Flags:       flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover: []uint64{0xc0dec0dec0000001, 0xc0dec0dec0000010, 0xc0dec0dec0000020, 0xc0dec0dec0000040,
				0xc0dec0dec0000100, 0xc0dec0dec0001000, 0xc0dec0dec0002000},
			Signal: []uint64{0xc0dec0dec0001100, 0xc0dec0dec0000140, 0xc0dec0dec0000011, 0xc0dec0dec0000001},
		},
		{
			Is64Bit: false,
			Input: makeCover32(0xc0000001, 0xc0000010, 0xc0000020, 0xc0000040,
				0xc0000100, 0xc0001000, 0xc0002000),
			CoverFilter: []uint64{0xc0000002, 0xc0000100},
			Flags:       flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover: []uint64{0xc0000001, 0xc0000010, 0xc0000020, 0xc0000040,
				0xc0000100, 0xc0001000, 0xc0002000},
			Signal: []uint64{0xc0001100, 0xc0000140, 0xc0000011, 0xc0000001},
		},
		// Extra coverage.
		{
			Is64Bit:       true,
			ExtraCoverage: true,
			Input:         makeCover64(0xc0dec0dec0000001, 0xc0dec0dec0000010),
			Flags:         flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover,
			Cover:         []uint64{0xc0dec0dec0000001, 0xc0dec0dec0000010},
			Signal:        []uint64{0xc0dec0dec0000011, 0xc0dec0dec0000001},
		},
	}
	executor := csource.BuildExecutor(t, target, "../../")
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			source := queue.Plain()
			vmArch := targets.TestArch32
			if test.Is64Bit {
				vmArch = targets.TestArch64
			}
			sysTarget := targets.Get(targets.TestOS, vmArch)
			if sysTarget.BrokenCompiler != "" {
				t.Skipf("skipping due to broken compiler:\n%v", sysTarget.BrokenCompiler)
			}
			ctx := startRPCServer(t, target, executor, source, rpcParams{
				vmArch:      vmArch,
				maxSignal:   test.MaxSignal,
				coverFilter: test.CoverFilter,
			})
			testCover1(t, ctx, target, test, source)
		})
	}
}

func testCover1(t *testing.T, ctx context.Context, target *prog.Target, test CoverTest, source *queue.PlainQueue) {
	callName := "syz_inject_cover"
	if test.ExtraCoverage {
		callName = "syz_inject_remote_cover"
	}
	text := fmt.Sprintf(`%s(&AUTO="%s", AUTO)`, callName, hex.EncodeToString(test.Input))
	p, err := target.Deserialize([]byte(text), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	req := &queue.Request{
		Prog: p,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags:  flatrpc.ExecEnvSignal | flatrpc.ExecEnvExtraCover | flatrpc.ExecEnvSandboxNone,
			ExecFlags: test.Flags,
		},
	}
	if test.ReturnAllSignal {
		req.ReturnAllSignal = []int{0}
	}
	source.Submit(req)
	res := req.Wait(ctx)
	if res.Err != nil || res.Info == nil || len(res.Info.Calls) != 1 || res.Info.Calls[0] == nil {
		t.Fatalf("program execution failed: status=%v err=%v\n%s", res.Status, res.Err, res.Output)
	}
	call := res.Info.Calls[0]
	if test.ExtraCoverage {
		call = res.Info.Extra
		if call == nil {
			t.Fatalf("got no extra coverage info")
		}
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
	assert.ElementsMatch(t, test.Comps, call.Comps)
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

type rpcParams struct {
	manyProcs      bool
	vmArch         string
	vmType         string
	maxSignal      []uint64
	coverFilter    []uint64
	machineChecked func(features flatrpc.Feature)
}

func startRPCServer(t *testing.T, target *prog.Target, executor string,
	source queue.Source, extra rpcParams) context.Context {
	dir, err := os.MkdirTemp("", "syz-runtest")
	if err != nil {
		t.Fatal(err)
	}
	ctx, done := context.WithCancel(context.Background())

	procs := runtime.GOMAXPROCS(0)
	if !extra.manyProcs {
		// We don't need many procs for this test.
		procs = min(procs, 4)
	}
	var output bytes.Buffer
	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:   target,
				VMType:   extra.vmType,
				Cover:    true,
				Debug:    *flagDebug,
				Features: flatrpc.AllFeatures,
				Sandbox:  flatrpc.ExecEnvSandboxNone,
			},
			VMArch:        extra.vmArch,
			Procs:         procs,
			Slowdown:      10, // to deflake slower tests
			DebugTimeouts: true,
		},
		Executor:    executor,
		Dir:         dir,
		GDB:         *flagGDB,
		MaxSignal:   extra.maxSignal,
		CoverFilter: extra.coverFilter,
		// Note that when *flagGDB is set, the option is ignored.
		OutputWriter: &output,
	}
	cfg.MachineChecked = func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
		if extra.machineChecked != nil {
			extra.machineChecked(features)
		}
		return source
	}
	errc := make(chan error)
	go func() {
		err := rpcserver.RunLocal(ctx, cfg)
		done()
		errc <- err
	}()
	t.Cleanup(func() {
		done()
		if err := <-errc; err != nil {
			t.Logf("executor output:\n%s", output.String())
			t.Fatal(err)
		}
		// We need to retry b/c we don't wait for all executor subprocesses (only set PR_SET_PDEATHSIG),
		// so t.TempDir() leads to episodic "directory not empty" failures.
		for i := 0; ; i++ {
			if err := os.RemoveAll(dir); err == nil {
				break
			}
			if i < 100 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			t.Logf("executor output:\n%s", output.String())
			t.Fatalf("failed to remove temp dir %v: %v", dir, err)
		}
	})
	return ctx
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
					// syz_mount_image tests are very large and this test takes too long.
					// syz-imagegen that generates does some of this testing (Deserialize/SerializeForExec).
					requires := map[string]bool{"manual": false}
					p, _, _, err := parseProg(target, dir, file, requires)
					if err != nil {
						t.Errorf("failed to parse %v: %v", file, err)
					}
					if p == nil {
						continue
					}
					if runtime.GOOS != sysTarget.BuildOS {
						continue // we need at least preprocessor binary to generate sources
					}
					if _, err = csource.Write(p, csource.ExecutorOpts); err != nil {
						t.Errorf("failed to generate C source for %v: %v", file, err)
					}
				}
			})
		}
	}
}
