// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

const timeout = 10 * time.Second

func buildExecutor(t *testing.T, target *prog.Target) string {
	src := fmt.Sprintf("../../executor/executor_%v.cc", target.OS)
	return buildProgram(t, target, filepath.FromSlash(src))
}

func buildSource(t *testing.T, target *prog.Target, src []byte) string {
	tmp, err := osutil.WriteTempFile(src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmp)
	return buildProgram(t, target, tmp)
}

func buildProgram(t *testing.T, target *prog.Target, src string) string {
	bin, err := csource.Build(target, "c++", src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return bin
}

func initTest(t *testing.T) (*prog.Target, rand.Source, int, uint64) {
	t.Parallel()
	iters := 100
	if testing.Short() {
		iters = 10
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	flags := cfg.Flags & (FlagUseShmem | FlagUseForkServer)
	return target, rs, iters, flags
}

func TestEmptyProg(t *testing.T) {
	target, _, _, flags0 := initTest(t)

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	cfg := Config{
		Flags:   flags0,
		Timeout: timeout,
	}
	env, err := MakeEnv(bin, 0, cfg)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()

	p := new(prog.Prog)
	opts := &ExecOpts{}
	output, _, failed, hanged, err := env.Exec(opts, p)
	if err != nil {
		t.Fatalf("failed to run executor: %v", err)
	}
	if len(output) != 0 {
		t.Fatalf("output on empty program")
	}
	if failed || hanged {
		t.Fatalf("empty program failed")
	}
}

func TestExecute(t *testing.T) {
	target, rs, iters, flags0 := initTest(t)

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	flags := []uint64{0, FlagThreaded, FlagThreaded | FlagCollide}
	for _, flag := range flags {
		t.Logf("testing flags 0x%x\n", flag)
		cfg := Config{
			Flags:   flag | flags0,
			Timeout: timeout,
		}
		env, err := MakeEnv(bin, 0, cfg)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < iters/len(flags); i++ {
			p := target.Generate(rs, 10, nil)
			opts := &ExecOpts{}
			output, _, _, _, err := env.Exec(opts, p)
			if err != nil {
				t.Logf("program:\n%s\n", p.Serialize())
				t.Fatalf("failed to run executor: %v\n%s", err, output)
			}
		}
	}
}
