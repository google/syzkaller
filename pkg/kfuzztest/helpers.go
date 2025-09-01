// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"path"
	"strings"

	"github.com/google/syzkaller/prog"
)

const syzKfuzzTestRun string = "syz_kfuzztest_run"

// Common prefix that all discriminated syz_kfuzztest_run pseudo-syscalls share.
const KfuzzTestTargetPrefix string = syzKfuzzTestRun + "$"

func GetTestName(syscall *prog.Syscall) (string, bool) {
	if syscall.CallName != syzKfuzzTestRun {
		return "", false
	}
	return strings.CutPrefix(syscall.Name, KfuzzTestTargetPrefix)
}

const kFuzzTestDir string = "/sys/kernel/debug/kfuzztest"
const inputFile string = "input"

func GetInputFilepath(testName string) string {
	return path.Join(kFuzzTestDir, testName, inputFile)
}
