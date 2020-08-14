// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
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

// This is the main configuration used by executor, so we want to test it as well.
var executorOpts = Options{
	Threaded:  true,
	Collide:   true,
	Repeat:    true,
	Procs:     2,
	Sandbox:   "none",
	Repro:     true,
	UseTmpDir: true,
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
		opts = append(opts, executorOpts)
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

func TestSysTests(t *testing.T) {
	t.Parallel()
	for _, target := range prog.AllTargets() {
		target := target
		sysTarget := targets.Get(target.OS, target.Arch)
		if runtime.GOOS != sysTarget.BuildOS {
			continue // we need at least preprocessor binary to generate sources
		}
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join("..", "..", "sys", target.OS, "test")
			if !osutil.IsExist(dir) {
				return
			}
			files, err := ioutil.ReadDir(dir)
			if err != nil {
				t.Fatalf("failed to read %v: %v", dir, err)
			}
			for _, finfo := range files {
				file := filepath.Join(dir, finfo.Name())
				if strings.HasSuffix(file, "~") || strings.HasSuffix(file, ".swp") {
					continue
				}
				data, err := ioutil.ReadFile(file)
				if err != nil {
					t.Fatalf("failed to read %v: %v", file, err)
				}
				p, err := target.Deserialize(data, prog.Strict)
				if err != nil {
					t.Fatalf("failed to parse program %v: %v", file, err)
				}
				_, err = Write(p, executorOpts)
				if err != nil {
					t.Fatalf("failed to generate C source for %v: %v", file, err)
				}
			}
		})
	}
}

func TestExecutorMacros(t *testing.T) {
	// Ensure that executor does not mis-spell any of the SYZ_* macros.
	target, _ := prog.GetTarget("test", "64")
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
