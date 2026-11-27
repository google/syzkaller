// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Build builds a C program from source src and returns name of the resulting binary.
func Build(target *prog.Target, src []byte) (string, error) {
	return build(target, src, "", "")
}

// BuildNoWarn is the same as Build, but ignores all compilation warnings.
// Should not be used in tests, but may be used e.g. when we are bisecting and potentially
// using an old repro with newer compiler, or a compiler that we never seen before.
// In these cases it's more important to build successfully.
func BuildNoWarn(target *prog.Target, src []byte) (string, error) {
	return build(target, src, "", "", "-fpermissive", "-w")
}

// BuildExecutor builds the executor binary for tests.
// rootDir must point to syzkaller root directory in slash notation.
func BuildExecutor(t *testing.T, target *prog.Target, rootDir string, cflags ...string) string {
	// Build w/o optimizations for tests. Tests can build lots of versions of executor in parallel,
	// and on overloaded machines it can be slow. On my machine this reduces executor build time
	// from ~7.5 to ~3.5 secs.
	cflags = append(cflags, "-O0")
	bin, err := build(target, nil, filepath.FromSlash(rootDir),
		filepath.FromSlash("executor/executor.cc"), cflags...)
	if err != nil {
		t.Fatalf("failed to build executor: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(bin)
	})
	return bin
}

func build(target *prog.Target, src []byte, dir, file string, cflags ...string) (string, error) {
	tempBase := ""
	if file == "" && runtime.GOOS == "linux" {
		// Avoid $TMPDIR values that bwrap forbids (e.g. /var/tmp) or cannot traverse as syzkaller.
		tempBase = "/tmp"
	}
	tempDir, err := os.MkdirTemp(tempBase, "syz-build-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	// Compile into a temporary directory rather than bind-mounting the output file directly:
	// linkers unlink or rename over the -o path, which fails with EBUSY on a file mount.
	const outName = "syz-executor"
	outBin := filepath.Join(tempDir, outName)
	if file == "" {
		// Relative to cmd.Dir (tempDir) so symlinked temp paths still match inside bwrap.
		outBin = outName
	}

	sysTarget := targets.Get(target.OS, target.Arch)
	compiler, flags := compilerArgs(target, sysTarget, outBin, file, cflags)
	cmd := osutil.Command(compiler, flags...)
	cmd.Dir = dir
	if file == "" {
		if err := osutil.SandboxChown(tempDir); err != nil {
			return "", err
		}
		cmd.Dir = tempDir
		cmd.Stdin = bytes.NewReader(src)
		// C sources can come from untrusted places (e.g. LLM-generated C reproducers),
		// where #include or .incbin would otherwise read arbitrary host files into diagnostics.
		if err := osutil.Sandbox(cmd,
			osutil.SandboxMountRW(tempDir),
			osutil.SandboxMountRO(sysTarget.ToolchainDirs()...)); err != nil {
			return "", err
		}
	}
	out, err := osutil.Run(5*time.Minute, cmd)
	if err != nil {
		if file != "" {
			src, _ = os.ReadFile(file)
		}
		return "", fmt.Errorf("failed to build program: %w\n%s\n%s\ncompiler invocation: %v %v",
			err, src, out, compiler, flags)
	}
	// We call the binary syz-executor because it sometimes shows in bug titles,
	// and we don't want 2 different bugs for when a crash is triggered during fuzzing and during repro.
	bin, err := osutil.TempFile("syz-executor")
	if err != nil {
		return "", err
	}
	// Copy via SandboxRoot so a compromised sandboxed compiler cannot replace syz-executor
	// with a symlink to a host file and have the privileged parent copy it out.
	root, err := osutil.OpenSandboxRoot(tempDir)
	if err != nil {
		os.Remove(bin)
		return "", err
	}
	defer root.Close()
	if err := root.CopyFileTo(outName, bin); err != nil {
		os.Remove(bin)
		return "", err
	}
	if err := os.Chmod(bin, osutil.DefaultExecPerm); err != nil {
		os.Remove(bin)
		return "", err
	}
	return bin, nil
}

func compilerArgs(target *prog.Target, sysTarget *targets.Target, outBin, file string,
	cflags []string) (string, []string) {
	flags := []string{
		"-o", outBin,
		"-DGOOS_" + target.OS + "=1",
		"-DGOARCH_" + target.Arch + "=1",
		"-DHOSTGOOS_" + runtime.GOOS + "=1",
	}
	if file == "" {
		flags = append(flags, "-x", "c", "-")
	} else {
		flags = append(flags, file)
	}
	compiler, targetCFlags := sysTarget.CCompiler, sysTarget.CFlags
	if file != "" && !strings.HasSuffix(file, ".c") {
		compiler, targetCFlags = sysTarget.CxxCompiler, sysTarget.CxxFlags
	}
	flags = append(flags, targetCFlags...)
	flags = append(flags, cflags...)
	if sysTarget.PtrSize == 4 {
		// We do generate uint64's for syscall arguments that overflow longs on 32-bit archs.
		flags = append(flags, "-Wno-overflow")
	}
	return compiler, flags
}

// Format reformats C source using clang-format.
func Format(src []byte) ([]byte, error) {
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	cmd := osutil.Command("clang-format", "-assume-filename=/src.c", "-style", style)
	cmd.Stdin = bytes.NewReader(src)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return src, fmt.Errorf("failed to format source: %w\n%v", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Something acceptable for kernel developers and email-friendly.
var style = `{
BasedOnStyle: LLVM,
IndentWidth: 2,
UseTab: Never,
BreakBeforeBraces: Linux,
IndentCaseLabels: false,
DerivePointerAlignment: false,
PointerAlignment: Left,
AlignTrailingComments: true,
AllowShortBlocksOnASingleLine: false,
AllowShortCaseLabelsOnASingleLine: false,
AllowShortFunctionsOnASingleLine: false,
AllowShortIfStatementsOnASingleLine: false,
AllowShortLoopsOnASingleLine: false,
ColumnLimit: 80,
}`
