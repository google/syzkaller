// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestGenerate(t *testing.T) {
	t.Parallel()
	for _, target := range prog.AllTargets() {
		switch target.OS {
		case "netbsd", "windows":
			continue
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
			if target.OS == "test" && target.PtrSize == 4 {
				// The same reason as linux/32.
				t.Skip("broken")
			}
			t.Parallel()
			testTarget(t, target)
		})
	}
}

func testTarget(t *testing.T, target *prog.Target) {
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	r := rand.New(rs)
	progs := []*prog.Prog{target.GenerateSimpleProg()}
	if p := target.GenerateAllSyzProg(rs); len(p.Calls) != 0 {
		progs = append(progs, p)
	}
	if !testing.Short() {
		progs = append(progs, target.Generate(rs, 10, nil))
	}
	opts := allOptionsSingle(target.OS)
	opts = append(opts, Options{
		Threaded:  true,
		Collide:   true,
		Repeat:    true,
		Procs:     2,
		Sandbox:   "none",
		Repro:     true,
		UseTmpDir: true,
	})
	allPermutations := allOptionsPermutations(target.OS)
	if testing.Short() {
		for i := 0; i < 16; i++ {
			opts = append(opts, allPermutations[r.Intn(len(allPermutations))])
		}
	} else {
		opts = allPermutations
	}
	for pi, p := range progs {
		for opti, opts := range opts {
			p, opts := p, opts
			t.Run(fmt.Sprintf("%v/%v", pi, opti), func(t *testing.T) {
				t.Parallel()
				testOne(t, p, opts)
			})
		}
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
		if strings.Contains(err.Error(), "no target compiler") {
			t.Skip(err)
		}
		t.Logf("opts: %+v\nprogram:\n%s\n", opts, p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
