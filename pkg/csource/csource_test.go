// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
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
			if target.OS == "linux" && target.Arch == "arm64" {
				// Episodically fails on travis with:
				// collect2: error: ld terminated with signal 11 [Segmentation fault]
				t.Skip("broken")
			}
			if target.OS == "test" && target.PtrSize == 4 {
				// The same reason as linux/32.
				t.Skip("broken")
			}
			if _, err := exec.LookPath(sysTarget.CCompiler); err != nil {
				t.Skipf("no target compiler %v", sysTarget.CCompiler)
			}
			full := !checked[target.OS]
			checked[target.OS] = true
			t.Parallel()
			testTarget(t, target, full)
		})

	}
}

func testTarget(t *testing.T, target *prog.Target, full bool) {
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	p := target.Generate(rs, 10, nil)
	p.Calls = append(p.Calls, target.GenerateAllSyzProg(rs).Calls...)
	var opts []Options
	if !full || testing.Short() {
		opts = allOptionsSingle(target.OS)
		// This is the main configuration used by executor,
		// so we want to test it as well.
		opts = append(opts, Options{
			Threaded:  true,
			Collide:   true,
			Repeat:    true,
			Procs:     2,
			Sandbox:   "none",
			Repro:     true,
			UseTmpDir: true,
		})
	} else {
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

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	src, err := Write(p, opts)
	if err != nil {
		t.Logf("opts: %+v\nprogram:\n%s\n", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	bin, err := Build(p.Target, src)
	if err != nil {
		t.Logf("opts: %+v\nprogram:\n%s\n", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
