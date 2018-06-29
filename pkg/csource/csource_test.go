// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestGenerateOne(t *testing.T) {
	t.Parallel()
	opts := Options{
		Threaded:  true,
		Collide:   true,
		Repeat:    true,
		Procs:     2,
		Sandbox:   "none",
		Repro:     true,
		UseTmpDir: true,
	}
	for _, target := range prog.AllTargets() {
		if target.OS == "test" {
			continue
		}
		if target.OS == "fuchsia" && !strings.Contains(os.Getenv("SOURCEDIR"), "fuchsia") {
			continue
		}
		if target.OS == "windows" {
			continue // TODO(dvyukov): support windows
		}
		target := target
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			if target.OS == "linux" && target.Arch == "arm" {
				// This currently fails (at least with my arm-linux-gnueabihf-gcc-4.8) with:
				// Assembler messages:
				// Error: alignment too large: 15 assumed
				t.Skip("broken")
			}
			if target.OS == "linux" && target.Arch == "386" {
				// Currently fails on travis with:
				// fatal error: asm/unistd.h: No such file or directory
				t.Skip("broken")
			}
			t.Parallel()
			rs := rand.NewSource(0)
			p := target.GenerateAllSyzProg(rs)
			if len(p.Calls) == 0 {
				t.Skip("no syz syscalls")
			}
			testOne(t, p, opts)
		})
	}
}

func TestGenerateOptionsHost(t *testing.T) {
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	testGenerateOptions(t, target)
}

func TestGenerateOptionsFuchsia(t *testing.T) {
	if !strings.Contains(os.Getenv("SOURCEDIR"), "fuchsia") {
		t.Skip("SOURCEDIR is not set")
	}
	target, err := prog.GetTarget("fuchsia", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	testGenerateOptions(t, target)
}

func testGenerateOptions(t *testing.T, target *prog.Target) {
	t.Parallel()
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	r := rand.New(rs)
	syzProg := target.GenerateAllSyzProg(rs)
	t.Logf("syz program:\n%s\n", syzProg.Serialize())
	permutations := allOptionsSingle(target.OS)
	allPermutations := allOptionsPermutations(target.OS)
	if testing.Short() {
		for i := 0; i < 16; i++ {
			permutations = append(permutations, allPermutations[r.Intn(len(allPermutations))])
		}
	} else {
		permutations = allPermutations
	}
	for i, opts := range permutations {
		opts := opts
		rs1 := rand.NewSource(r.Int63())
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			t.Parallel()
			t.Logf("opts: %+v", opts)
			if !testing.Short() {
				p := target.Generate(rs1, 10, nil)
				testOne(t, p, opts)
			}
			testOne(t, syzProg, opts)
		})
	}
}

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	src, err := Write(p, opts)
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	bin, err := Build(p.Target, src)
	if err == ErrNoCompiler {
		t.Skip(err)
	}
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
