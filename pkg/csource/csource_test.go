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
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

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
		})
	}
}

func testTarget(t *testing.T, target *prog.Target, full bool) {
	seed := time.Now().UnixNano()
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
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
	for opti, opts := range opts {
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
res = syscall(SYS_csource0, 1);
if (res != -1)
	r[0] = res;
syscall(SYS_csource1, r[0]);
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
			output: `
NONFAILING(memcpy((void*)0x20000040, "\x12\x34\x56\x78", 4));
syscall(SYS_csource2, 0x20000040ul);
NONFAILING(memset((void*)0x20000080, 0, 10));
syscall(SYS_csource3, 0x20000080ul);
NONFAILING(memset((void*)0x200000c0, 48, 10));
syscall(SYS_csource4, 0x200000c0ul);
NONFAILING(memcpy((void*)0x20000100, "0101010101", 10));
syscall(SYS_csource5, 0x20000100ul);
NONFAILING(memcpy((void*)0x20000140, "101010101010", 12));
syscall(SYS_csource6, 0x20000140ul);
`,
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
