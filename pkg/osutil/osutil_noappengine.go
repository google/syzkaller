// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !appengine

package osutil

import (
	"os/exec"
)

func exitCode(err error) int {
	if exitError, ok := err.(*exec.ExitError); ok {
		return exitError.ProcessState.ExitCode()
	}
	return 0
}
