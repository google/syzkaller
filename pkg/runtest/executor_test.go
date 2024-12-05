// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package runtest

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

// Find the corresponding QEMU binary for the target arch, if needed.
func qemuBinary(arch string) (string, error) {
	qarch, ok := map[string]string{
		"386":      "i386",
		"amd64":    "x86_64",
		"arm64":    "aarch64",
		"arm":      "arm",
		"mips64le": "mips64el",
		"ppc64le":  "ppc64le",
		"riscv64":  "riscv64",
		"s390x":    "s390x",
	}[arch]
	if !ok {
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}

	qemuBinary := "qemu-" + qarch
	path, err := exec.LookPath(qemuBinary)
	if err != nil {
		return "", fmt.Errorf("qemu binary not found in PATH: %s", qemuBinary)
	}

	return filepath.Base(path), nil
}

// If the tests are running on CI, or if there is an assertion failure in the executor,
// report a fatal error. Otherwise, assume cross-arch execution does not work, and skip
// the test.
func handleCrossArchError(t *testing.T, err error) {
	if os.Getenv("CI") != "" || strings.Contains(err.Error(), "SYZFAIL:") {
		t.Fatal(err)
	} else {
		t.Skipf("skipping, cross-arch execution failed: %v", err)
	}
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
			dir := t.TempDir()
			target, err := prog.GetTarget(runtime.GOOS, sysTarget.Arch)
			if err != nil {
				t.Fatal(err)
			}
			bin := csource.BuildExecutor(t, target, "../..")
			if sysTarget.Arch == runtime.GOARCH || sysTarget.VMArch == runtime.GOARCH {
				// Execute the tests natively.
				if _, err := osutil.RunCmd(time.Minute, dir, bin, "test"); err != nil {
					t.Fatal(err)
				}
			} else {
				// Get QEMU binary for the target arch. This code might run inside Docker, so it cannot
				// rely on binfmt_misc handlers provided by qemu-user.
				qemu, err := qemuBinary(sysTarget.Arch)
				if err != nil {
					handleCrossArchError(t, err)
				}
				if _, err := osutil.RunCmd(time.Minute, dir, qemu, bin, "test"); err != nil {
					handleCrossArchError(t, err)
				}
			}
		})
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
	executor := csource.BuildExecutor(t, target, "../..")
	source := queue.Plain()
	startRPCServer(t, target, executor, source, rpcParams{manyProcs: true})
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
		req := &queue.Request{
			Prog:         p,
			ReturnError:  true,
			ReturnOutput: true,
			ExecOpts: flatrpc.ExecOpts{
				EnvFlags: flatrpc.ExecEnvSandboxNone,
			},
		}
		source.Submit(req)
		res := req.Wait(context.Background())
		if res.Err != nil {
			t.Fatalf("program execution failed: %v\n%s", res.Err, res.Output)
		}
		if res.Info.Calls[0].Error != 0 {
			t.Fatalf("data comparison failed: %v\n%s", res.Info.Calls[0].Error, res.Output)
		}
	}
}

func TestExecutorCommonExt(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget("test", "64_fork")
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..", "-DSYZ_TEST_COMMON_EXT_EXAMPLE=1")
	// The example setup_ext_test does:
	// *(uint64*)(SYZ_DATA_OFFSET + 0x1234) = 0xbadc0ffee;
	// The following program tests that that value is present at 0x1234.
	test := `syz_compare(&(0x7f0000001234)="", 0x8, &(0x7f0000000000)=@blob="eeffc0ad0b000000", AUTO)`
	p, err := target.Deserialize([]byte(test), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	source := queue.Plain()
	startRPCServer(t, target, executor, source, rpcParams{})
	req := &queue.Request{
		Prog:         p,
		ReturnError:  true,
		ReturnOutput: true,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags: flatrpc.ExecEnvSandboxNone,
		},
	}
	source.Submit(req)
	res := req.Wait(context.Background())
	if res.Err != nil {
		t.Fatalf("program execution failed: %v\n%s", res.Err, res.Output)
	}
	if call := res.Info.Calls[0]; call.Flags&flatrpc.CallFlagFinished == 0 || call.Error != 0 {
		t.Fatalf("bad call result: flags=%x errno=%v", call.Flags, call.Error)
	}
}
