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

func initTest(t *testing.T) (rand.Source, int) {
	t.Parallel()
	iters := 100
	if testing.Short() {
		iters = 10
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func TestEmptyProg(t *testing.T) {
	target, err := prog.GetTarget("linux", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	cfg := Config{
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
	rs, iters := initTest(t)
	flags := []uint64{0, FlagThreaded, FlagThreaded | FlagCollide}

	target, err := prog.GetTarget("linux", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	for _, flag := range flags {
		t.Logf("testing flags 0x%x\n", flag)
		cfg := Config{
			Flags:   flag,
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
