// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/csource"
	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/prog"
)

const timeout = 10 * time.Second

func buildExecutor(t *testing.T) string {
	return buildProgram(t, "../executor/executor.cc")
}

func buildSource(t *testing.T, src []byte) string {
	tmp, err := fileutil.WriteTempFile(src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmp)
	return buildProgram(t, tmp)
}

func buildProgram(t *testing.T, src string) string {
	bin, err := csource.Build("c++", src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return bin
}

func initTest(t *testing.T) (rand.Source, int) {
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
	bin := buildExecutor(t)
	defer os.Remove(bin)

	env, err := MakeEnv(bin, timeout, 0, 0)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()

	p := new(prog.Prog)
	output, _, failed, hanged, err := env.Exec(p, false, false)
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
	bin := buildExecutor(t)
	defer os.Remove(bin)

	rs, iters := initTest(t)
	flags := []uint64{0, FlagThreaded, FlagThreaded | FlagCollide}
	for _, flag := range flags {
		t.Logf("testing flags 0x%x\n", flag)
		env, err := MakeEnv(bin, timeout, flag, 0)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < iters/len(flags); i++ {
			p := prog.Generate(rs, 10, nil)
			output, _, _, _, err := env.Exec(p, false, false)
			if err != nil {
				t.Logf("program:\n%s\n", p.Serialize())
				t.Fatalf("failed to run executor: %v\n%s", err, output)
			}
		}
	}
}
