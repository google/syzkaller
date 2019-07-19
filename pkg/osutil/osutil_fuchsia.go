// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build fuchsia,!appengine

package osutil

import (
	"fmt"
	"os"
	"os/exec"
)

func HandleInterrupts(shutdown chan struct{}) {
}

func RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func SystemMemorySize() uint64 {
	return 0
}

func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	return nil, nil, fmt.Errorf("CreateMemMappedFile is not implemented")
}

func CloseMemMappedFile(f *os.File, mem []byte) error {
	return fmt.Errorf("CloseMemMappedFile is not implemented")
}

func ProcessExitStatus(ps *os.ProcessState) int {
	// TODO: can be extracted from ExitStatus string.
	return 0
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

func killPgroup(cmd *exec.Cmd) {
}
