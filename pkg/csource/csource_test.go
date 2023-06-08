// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func init() {
	// csource tests consume too much memory under race detector (>1GB),
	// and periodically timeout on Travis. So we skip them.
	if testutil.RaceEnabled {
		for _, arg := range os.Args[1:] {
			if strings.Contains(arg, "-test.short") {
				fmt.Printf("skipping race testing in short mode\n")
				os.Exit(0)
			}
		}
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	checked := make(map[string]bool)
	for _, target := range prog.AllTargets() {
		target := target
		sysTarget := targets.Get(target.OS, target.Arch)
		if runtime.GOOS != sysTarget.BuildOS {
			continue
		}
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			full := !checked[target.OS]
			if !full && testing.Short() {
				return
			}
			if err := sysTarget.BrokenCompiler; err != "" {
				t.Skipf("target compiler is broken: %v", err)
			}
			checked[target.OS] = true
			t.Parallel()
			testTarget(t, target, full)
			testPseudoSyscalls(t, target)
		})
	}
}

func testPseudoSyscalls(t *testing.T, target *prog.Target) {
	// Use options that are as minimal as possible.
	// We want to ensure that the code can always be compiled.
	opts := Options{
		Slowdown: 1,
	}
	rs := testutil.RandSource(t)
	for _, meta := range target.PseudoSyscalls() {
		p := target.GenSampleProg(meta, rs)
		t.Run(fmt.Sprintf("single_%s", meta.CallName), func(t *testing.T) {
			t.Parallel()
			testOne(t, p, opts)
		})
	}
}

func testTarget(t *testing.T, target *prog.Target, full bool) {
	rs := testutil.RandSource(t)
	p := target.Generate(rs, 10, target.DefaultChoiceTable())
	// Turns out that fully minimized program can trigger new interesting warnings,
	// e.g. about NULL arguments for functions that require non-NULL arguments in syz_ functions.
	// We could append both AllSyzProg as-is and a minimized version of it,
	// but this makes the NULL argument warnings go away (they showed up in ".constprop" versions).
	// Testing 2 programs takes too long since we have lots of options permutations and OS/arch.
	// So we use the as-is in short tests and minimized version in full tests.
	syzProg := target.GenerateAllSyzProg(rs)
	var opts []Options
	if !full || testing.Short() {
		p.Calls = append(p.Calls, syzProg.Calls...)
		opts = allOptionsSingle(target.OS)
		opts = append(opts, ExecutorOpts)
	} else {
		minimized, _ := prog.Minimize(syzProg, -1, false, func(p *prog.Prog, call int) bool {
			return len(p.Calls) == len(syzProg.Calls)
		})
		p.Calls = append(p.Calls, minimized.Calls...)
		opts = allOptionsPermutations(target.OS)
	}
	// Test various call properties.
	if len(p.Calls) > 0 {
		p.Calls[0].Props.FailNth = 1
	}
	if len(p.Calls) > 1 {
		p.Calls[1].Props.Async = true
	}
	if len(p.Calls) > 2 {
		p.Calls[2].Props.Rerun = 4
	}
	for opti, opts := range opts {
		if testing.Short() && opts.HandleSegv {
			// HandleSegv can radically increase compilation time/memory consumption on large programs.
			// For example, for one program captured from this test enabling HandleSegv increases
			// compilation time from 1.94s to 104.73s and memory consumption from 136MB to 8116MB.
			continue
		}
		opts := opts
		t.Run(fmt.Sprintf("%v", opti), func(t *testing.T) {
			t.Parallel()
			testOne(t, p, opts)
		})
	}
}

var failedTests uint32

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	// Each failure produces lots of output (including full C source).
	// Frequently lots of tests fail at the same, which produces/tmp/log
	// tens of thounds of lines of output. Limit amount of output.
	maxFailures := uint32(10)
	if os.Getenv("CI") != "" {
		maxFailures = 1
	}
	if atomic.LoadUint32(&failedTests) > maxFailures {
		return
	}
	src, err := Write(p, opts)
	if err != nil {
		if atomic.AddUint32(&failedTests, 1) > maxFailures {
			t.Fatal()
		}
		t.Logf("opts: %+v\nprogram:\n%s\n", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	bin, err := Build(p.Target, src)
	if err != nil {
		if atomic.AddUint32(&failedTests, 1) > maxFailures {
			t.Fatal()
		}
		t.Logf("opts: %+v\nprogram:\n%s\n", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}

func TestExecutorMacros(t *testing.T) {
	// Ensure that executor does not mis-spell any of the SYZ_* macros.
	target, _ := prog.GetTarget(targets.TestOS, targets.TestArch64)
	p := target.Generate(rand.NewSource(0), 1, target.DefaultChoiceTable())
	expected := commonDefines(p, Options{})
	expected["SYZ_EXECUTOR"] = true
	expected["SYZ_HAVE_SETUP_LOOP"] = true
	expected["SYZ_HAVE_RESET_LOOP"] = true
	expected["SYZ_HAVE_SETUP_TEST"] = true
	expected["SYZ_TEST_COMMON_EXT_EXAMPLE"] = true
	macros := regexp.MustCompile("SYZ_[A-Za-z0-9_]+").FindAllString(commonHeader, -1)
	for _, macro := range macros {
		if strings.HasPrefix(macro, "SYZ_HAVE_") {
			continue
		}
		if _, ok := expected[macro]; !ok {
			t.Errorf("unexpected macro: %v", macro)
		}
	}
}

func TestSource(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	type Test struct {
		input  string
		output string
	}
	tests := []Test{
		{
			input: `
r0 = csource0(0x1)
csource1(r0)
`,
			output: `
res = syscall(SYS_csource0, /*num=*/1);
if (res != -1)
	r[0] = res;
syscall(SYS_csource1, /*fd=*/r[0]);
`,
		},
		{
			input: `
csource2(&AUTO="12345678")
csource3(&AUTO)
csource4(&AUTO)
csource5(&AUTO)
csource6(&AUTO)
`,
			output: fmt.Sprintf(`
NONFAILING(memcpy((void*)0x%x, "\x12\x34\x56\x78", 4));
syscall(SYS_csource2, /*buf=*/0x%xul);
NONFAILING(memset((void*)0x%x, 0, 10));
syscall(SYS_csource3, /*buf=*/0x%xul);
NONFAILING(memset((void*)0x%x, 48, 10));
syscall(SYS_csource4, /*buf=*/0x%xul);
NONFAILING(memcpy((void*)0x%x, "0101010101", 10));
syscall(SYS_csource5, /*buf=*/0x%xul);
NONFAILING(memcpy((void*)0x%x, "101010101010", 12));
syscall(SYS_csource6, /*buf=*/0x%xul);
`,
				target.DataOffset+0x40, target.DataOffset+0x40,
				target.DataOffset+0x80, target.DataOffset+0x80,
				target.DataOffset+0xc0, target.DataOffset+0xc0,
				target.DataOffset+0x100, target.DataOffset+0x100,
				target.DataOffset+0x140, target.DataOffset+0x140),
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.input), prog.Strict)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &context{
				target:    target,
				sysTarget: targets.Get(target.OS, target.Arch),
			}
			calls, _, err := ctx.generateProgCalls(p, false)
			if err != nil {
				t.Fatal(err)
			}
			got := regexp.MustCompile(`(\n|^)\t`).ReplaceAllString(strings.Join(calls, ""), "\n")
			if test.output != got {
				t.Fatalf("input:\n%v\nwant:\n%v\ngot:\n%v", test.input, test.output, got)
			}
		})
	}
}

func generateSandboxFunctionSignatureTestCase(t *testing.T, sandbox string, sandboxArg int, expected, message string) {
	actual := generateSandboxFunctionSignature(sandbox, sandboxArg)
	assert.Equal(t, actual, expected, message)
}

func TestGenerateSandboxFunctionSignature(t *testing.T) {
	// This test-case intentionally omits the following edge cases:
	// - sandbox name as whitespaces, tabs
	// - control chars \r, \n and unprintables
	// - unsuitable chars - punctuation, emojis, '#', '*', etc
	// - character case mismatching function prototype defined in common_linux.h.
	//   For example 'do_sandbox_android' and 'AnDroid'.
	// - non english letters, unicode compound characters
	// and focuses on correct handling of sandboxes supporting and not 'sandbox_arg'
	// config setting.
	generateSandboxFunctionSignatureTestCase(t,
		"",        // sandbox name
		0,         // sandbox arg
		"loop();", // expected
		"Empty sandbox name should produce 'loop();'")

	generateSandboxFunctionSignatureTestCase(t,
		"abrakadabra",               // sandbox name
		0,                           // sandbox arg
		"do_sandbox_abrakadabra();", // expected
		"Empty sandbox name should produce 'loop();'")

	generateSandboxFunctionSignatureTestCase(t,
		"android",                    // sandbox name
		-1234,                        // sandbox arg
		"do_sandbox_android(-1234);", // expected
		"Android sandbox function requires an argument")
}
