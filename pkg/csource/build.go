// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Build builds a C/C++ program from source src and returns name of the resulting binary.
// lang can be "c" or "c++".
func Build(target *prog.Target, lang, src string) (string, error) {
	sysTarget := targets.List[target.OS][target.Arch]
	compiler := sysTarget.CCompilerPrefix + "gcc"
	if _, err := exec.LookPath(compiler); err != nil {
		return "", ErrNoCompiler
	}
	// We call the binary syz-executor because it sometimes shows in bug titles,
	// and we don't want 2 different bugs for when a crash is triggered during fuzzing and during repro.
	bin, err := osutil.TempFile("syz-executor")
	if err != nil {
		return "", err
	}
	flags := []string{
		"-x", lang, "-Wall", "-Werror", "-O1", "-g", "-o", bin, src, "-pthread",
	}
	flags = append(flags, sysTarget.CrossCFlags...)
	if sysTarget.PtrSize == 4 {
		// We do generate uint64's for syscall arguments that overflow longs on 32-bit archs.
		flags = append(flags, "-Wno-overflow")
	}
	out, err := osutil.Command(compiler, append(flags, "-static")...).CombinedOutput()
	if err != nil {
		// Some distributions don't have static libraries.
		out, err = osutil.Command(compiler, flags...).CombinedOutput()
	}
	if err != nil {
		os.Remove(bin)
		data, _ := ioutil.ReadFile(src)
		return "", fmt.Errorf("failed to build program:\n%s\n%s\ncompiler invocation: %v %v",
			data, out, compiler, flags)
	}
	return bin, nil
}

var ErrNoCompiler = errors.New("no target compiler")

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
