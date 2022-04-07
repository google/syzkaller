// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	. "github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func buildExecutor(t *testing.T, target *prog.Target) string {
	src := filepath.FromSlash("../../executor/executor.cc")
	bin, err := csource.BuildFile(target, src)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func initTest(t *testing.T) (*prog.Target, rand.Source, int, bool, bool, targets.Timeouts) {
	t.Parallel()
	iters := 100
	if testing.Short() {
		iters = 10
	}
	seed := time.Now().UnixNano()
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	return target, rs, iters, cfg.UseShmem, cfg.UseForkServer, cfg.Timeouts
}

// TestExecutor runs all internal executor unit tests.
// We do it here because we already build executor binary here.
func TestExecutor(t *testing.T) {
	t.Parallel()
	for _, sysTarget := range targets.List[runtime.GOOS] {
		sysTarget := targets.Get(runtime.GOOS, sysTarget.Arch)
		t.Run(sysTarget.Arch, func(t *testing.T) {
			if sysTarget.BrokenCompiler != "" {
				t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
			}
			t.Parallel()
			target, err := prog.GetTarget(runtime.GOOS, sysTarget.Arch)
			if err != nil {
				t.Fatal(err)
			}
			bin := buildExecutor(t, target)
			defer os.Remove(bin)
			// qemu-user may allow us to run some cross-arch binaries.
			if _, err := osutil.RunCmd(time.Minute, "", bin, "test"); err != nil {
				if sysTarget.Arch == runtime.GOARCH || sysTarget.VMArch == runtime.GOARCH {
					t.Fatal(err)
				}
				t.Skipf("skipping, cross-arch binary failed: %v", err)
			}
		})
	}
}

func prepareTestProgram(target *prog.Target) *prog.Prog {
	p := target.DataMmapProg()
	if len(p.Calls) > 1 {
		p.Calls[1].Props.Async = true
	}
	return p
}

func TestExecute(t *testing.T) {
	target, _, _, useShmem, useForkServer, timeouts := initTest(t)

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	flags := []ExecFlags{0, FlagThreaded}
	for _, flag := range flags {
		t.Logf("testing flags 0x%x\n", flag)
		cfg := &Config{
			Executor:      bin,
			UseShmem:      useShmem,
			UseForkServer: useForkServer,
			Timeouts:      timeouts,
		}
		env, err := MakeEnv(cfg, 0)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < 10; i++ {
			p := prepareTestProgram(target)
			opts := &ExecOpts{
				Flags: flag,
			}
			output, info, hanged, err := env.Exec(opts, p)
			if err != nil {
				t.Fatalf("failed to run executor: %v", err)
			}
			if hanged {
				t.Fatalf("program hanged:\n%s", output)
			}
			if len(info.Calls) != len(p.Calls) {
				t.Fatalf("executed less calls (%v) than prog len(%v):\n%s", len(info.Calls), len(p.Calls), output)
			}
			if info.Calls[0].Errno != 0 {
				t.Fatalf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
			}
			if len(output) != 0 {
				t.Fatalf("output on empty program")
			}
		}
	}
}

func TestParallel(t *testing.T) {
	target, _, _, useShmem, useForkServer, timeouts := initTest(t)
	bin := buildExecutor(t, target)
	defer os.Remove(bin)
	cfg := &Config{
		Executor:      bin,
		UseShmem:      useShmem,
		UseForkServer: useForkServer,
		Timeouts:      timeouts,
	}
	const P = 10
	errs := make(chan error, P)
	for p := 0; p < P; p++ {
		p := p
		go func() {
			env, err := MakeEnv(cfg, p)
			if err != nil {
				errs <- fmt.Errorf("failed to create env: %v", err)
				return
			}
			defer func() {
				env.Close()
				errs <- err
			}()
			p := target.DataMmapProg()
			opts := &ExecOpts{}
			output, info, hanged, err := env.Exec(opts, p)
			if err != nil {
				err = fmt.Errorf("failed to run executor: %v", err)
				return
			}
			if hanged {
				err = fmt.Errorf("program hanged:\n%s", output)
				return
			}
			if len(info.Calls) == 0 {
				err = fmt.Errorf("no calls executed:\n%s", output)
				return
			}
			if info.Calls[0].Errno != 0 {
				err = fmt.Errorf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
				return
			}
			if len(output) != 0 {
				err = fmt.Errorf("output on empty program")
				return
			}
		}()
	}
	for p := 0; p < P; p++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
