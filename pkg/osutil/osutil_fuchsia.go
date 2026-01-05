// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build fuchsia

package osutil

import (
	"os"
)

func HandleInterrupts(shutdown chan struct{}) {
}

func ProcessExitStatus(ps *os.ProcessState) int {
	// TODO: can be extracted from ExitStatus string.
	return 0
}
