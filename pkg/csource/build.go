// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Build builds a C program from source src and returns name of the resulting binary.
func Build(target *prog.Target, src []byte) (string, error) {
	return build(target, src, "")
}

// BuildFile builds a C/C++ program from file src and returns name of the resulting binary.
func BuildFile(target *prog.Target, src string) (string, error) {
	return build(target, nil, src)
}

func build(target *prog.Target, src []byte, file string) (string, error) {
	sysTarget := targets.Get(target.OS, target.Arch)
	compiler := sysTarget.CCompiler
	if _, err := exec.LookPath(compiler); err != nil {
		return "", fmt.Errorf("no target compiler %v", compiler)
	}
	// We call the binary syz-executor because it sometimes shows in bug titles,
	// and we don't want 2 different bugs for when a crash is triggered during fuzzing and during repro.
	bin, err := osutil.TempFile("syz-executor")
	if err != nil {
		return "", err
	}

	flags := []string{
		"-Wall", "-Werror", "-O1", "-g", "-o", bin, "-pthread",
		"-DGOOS_" + target.OS + "=1",
		"-DGOARCH_" + target.Arch + "=1",
	}
	if file == "" {
		flags = append(flags, "-x", "c", "-")
	} else {
		flags = append(flags, file)
	}
	flags = append(flags, sysTarget.CrossCFlags...)
	if sysTarget.PtrSize == 4 {
		// We do generate uint64's for syscall arguments that overflow longs on 32-bit archs.
		flags = append(flags, "-Wno-overflow")
	}
	cmd := osutil.Command(compiler, flags...)
	if file == "" {
		cmd.Stdin = bytes.NewReader(src)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(bin)
		if file != "" {
			src, _ = ioutil.ReadFile(file)
		}
		return "", fmt.Errorf("failed to build program:\n%s\n%s\ncompiler invocation: %v %v",
			src, out, compiler, flags)
	}
	return bin, nil
}

// Format reformats C source using clang-format.
func Format(src []byte) ([]byte, error) {
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	cmd := osutil.Command("clang-format", "-assume-filename=/src.c", "-style", style)
	cmd.Stdin = bytes.NewReader(src)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return src, fmt.Errorf("failed to format source: %v\n%v", err, stderr.String())
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
