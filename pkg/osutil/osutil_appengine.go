// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build appengine

package osutil

import (
	"os/exec"
)

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	return nil
}

func SandboxChown(file string) error {
	return nil
}

func setPdeathsig(cmd *exec.Cmd) {
}

func killPgroup(cmd *exec.Cmd) {
}
