// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build freebsd,!appengine netbsd,!appengine

package osutil

import (
	"os"
	"os/exec"
)

func UmountAll(dir string) {
}

func prolongPipe(r, w *os.File) {
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	return nil
}

func SandboxChown(file string) error {
	return nil
}

func setPdeathsig(cmd *exec.Cmd) {
}
