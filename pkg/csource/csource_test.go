// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func initTest(t *testing.T) (*prog.Target, rand.Source, int) {
	t.Parallel()
	iters := 1
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := prog.GetTarget("linux", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return target, rs, iters
}

func TestGenerateOne(t *testing.T) {
	t.Parallel()
	opts := Options{
		Threaded:  true,
		Collide:   true,
		Repeat:    true,
		Procs:     2,
		Sandbox:   "namespace",
		Repro:     true,
		UseTmpDir: true,
	}
	for _, target := range prog.AllTargets() {
		if target.OS == "test" {
			continue
		}
		if target.OS == "fuchsia" {
			continue // TODO(dvyukov): support fuchsia
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

func TestGenerateOptions(t *testing.T) {
	target, rs, _ := initTest(t)
	syzProg := target.GenerateAllSyzProg(rs)
	t.Logf("syz program:\n%s\n", syzProg.Serialize())
	permutations := allOptionsSingle()
	allPermutations := allOptionsPermutations()
	if testing.Short() {
		r := rand.New(rs)
		for i := 0; i < 16; i++ {
			permutations = append(permutations, allPermutations[r.Intn(len(allPermutations))])
		}
	} else {
		permutations = allPermutations
	}
	for i, opts := range permutations {
		opts := opts
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			target, rs, iters := initTest(t)
			t.Logf("opts: %+v", opts)
			if !testing.Short() {
				for i := 0; i < iters; i++ {
					p := target.Generate(rs, 10, nil)
					testOne(t, p, opts)
				}
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
	srcf, err := osutil.WriteTempFile(src)
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(srcf)
	bin, err := Build(p.Target, "c", srcf)
	if err == ErrNoCompiler {
		t.Skip(err)
	}
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
