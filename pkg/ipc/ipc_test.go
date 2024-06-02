// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/image"
	. "github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func initTest(t *testing.T) (*prog.Target, rand.Source, int, bool, targets.Timeouts) {
	t.Parallel()
	iters := 100
	if testing.Short() {
		iters = 10
	}
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	rs := testutil.RandSource(t)
	return target, rs, iters, cfg.UseForkServer, cfg.Timeouts
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
			bin := csource.BuildExecutor(t, target, "../..")
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
	target, _, _, useForkServer, timeouts := initTest(t)

	bin := csource.BuildExecutor(t, target, "../..")

	flags := []flatrpc.ExecFlag{0, flatrpc.ExecFlagThreaded}
	for _, flag := range flags {
		t.Logf("testing flags 0x%x", flag)
		cfg := &Config{
			Executor:      bin,
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
			opts := &flatrpc.ExecOpts{
				ExecFlags: flag,
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
			if info.Calls[0].Error != 0 {
				t.Fatalf("simple call failed: %v\n%s", info.Calls[0].Error, output)
			}
			if len(output) != 0 {
				t.Fatalf("output on empty program")
			}
		}
	}
}

func TestParallel(t *testing.T) {
	target, _, _, useForkServer, timeouts := initTest(t)
	bin := csource.BuildExecutor(t, target, "../..")
	cfg := &Config{
		Executor:      bin,
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
				errs <- fmt.Errorf("failed to create env: %w", err)
				return
			}
			defer func() {
				env.Close()
				errs <- err
			}()
			p := target.DataMmapProg()
			opts := &flatrpc.ExecOpts{}
			output, info, hanged, err := env.Exec(opts, p)
			if err != nil {
				err = fmt.Errorf("failed to run executor: %w", err)
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
			if info.Calls[0].Error != 0 {
				err = fmt.Errorf("simple call failed: %v\n%s", info.Calls[0].Error, output)
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

func TestZlib(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	cfg, opts, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	opts.EnvFlags |= flatrpc.ExecEnvDebug
	cfg.Executor = csource.BuildExecutor(t, target, "../..")
	env, err := MakeEnv(cfg, 0)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()
	r := rand.New(testutil.RandSource(t))
	for i := 0; i < 10; i++ {
		data := testutil.RandMountImage(r)
		compressed := image.Compress(data)
		text := fmt.Sprintf(`syz_compare_zlib(&(0x7f0000000000)="$%s", AUTO, &(0x7f0000800000)="$%s", AUTO)`,
			image.EncodeB64(data), image.EncodeB64(compressed))
		p, err := target.Deserialize([]byte(text), prog.Strict)
		if err != nil {
			t.Fatalf("failed to deserialize empty program: %v", err)
		}
		output, info, _, err := env.Exec(opts, p)
		if err != nil {
			t.Fatalf("failed to run executor: %v", err)
		}
		if info.Calls[0].Error != 0 {
			t.Fatalf("data comparison failed: %v\n%s", info.Calls[0].Error, output)
		}
	}
}

func TestExecutorCommonExt(t *testing.T) {
	target, err := prog.GetTarget("test", "64_fork")
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	bin := csource.BuildExecutor(t, target, "../..", "-DSYZ_TEST_COMMON_EXT_EXAMPLE=1")
	out, err := osutil.RunCmd(time.Minute, "", bin, "setup", "0")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("example setup_ext called")) {
		t.Fatalf("setup_ext wasn't called:\n%s", out)
	}

	// The example setup_ext_test does:
	// *(uint64*)(SYZ_DATA_OFFSET + 0x1234) = 0xbadc0ffee;
	// The following program tests that that value is present at 0x1234.
	test := `syz_compare(&(0x7f0000001234)="", 0x8, &(0x7f0000000000)=@blob="eeffc0ad0b000000", AUTO)`
	p, err := target.Deserialize([]byte(test), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	cfg, opts, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Executor = bin
	opts.EnvFlags |= flatrpc.ExecEnvDebug
	env, err := MakeEnv(cfg, 0)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()
	_, info, _, err := env.Exec(opts, p)
	if err != nil {
		t.Fatal(err)
	}
	if call := info.Calls[0]; call.Flags&flatrpc.CallFlagFinished == 0 || call.Error != 0 {
		t.Fatalf("bad call result: flags=%x errno=%v", call.Flags, call.Error)
	}
}
