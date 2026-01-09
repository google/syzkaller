// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !linux

package osutil

import (
	"io/fs"
	"os"
	"os/exec"
	"time"
)

func fileTimes(file string) (time.Time, time.Time, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	// Creation time is not present in stat, so we use modification time for both.
	modTime := stat.ModTime()
	return modTime, modTime, nil
}

func RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func SystemMemorySize() uint64 {
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

func setPdeathsig(cmd *exec.Cmd, hardKill bool) {
}

func killPgroup(cmd *exec.Cmd) {
}

func sysDiskUsage(info fs.FileInfo) uint64 {
	return uint64(max(0, info.Size()))
}
