// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// ProcessTempDir creates a new temp dir in where and returns its path and an unique index.
// It also cleans up old, unused temp dirs after dead processes.
func ProcessTempDir(where string) (string, error) {
	for i := 0; i < 1e3; i++ {
		path := filepath.Join(where, fmt.Sprintf("instance-%v", i))
		pidfile := filepath.Join(path, ".pid")
		err := os.Mkdir(path, DefaultDirPerm)
		if os.IsExist(err) {
			// Try to clean up.
			if cleanupTempDir(path, pidfile) {
				i--
			}
			continue
		}
		if err != nil {
			return "", err
		}
		if err := WriteFile(pidfile, []byte(strconv.Itoa(syscall.Getpid()))); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("too many live instances")
}

func cleanupTempDir(path, pidfile string) bool {
	data, err := os.ReadFile(pidfile)
	if err == nil && len(data) > 0 {
		pid, err := strconv.Atoi(string(data))
		if err == nil && pid > 1 {
			err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(pid)).Run()
			if err == nil {
				if os.Remove(pidfile) == nil {
					return os.RemoveAll(path) == nil
				}
			}
		}
	}
	// If err != nil, assume that the pid file is not created yet.
	return false
}

func HandleInterrupts(shutdown chan struct{}) {
}

func RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func SystemMemorySize() uint64 {
	return 0
}

func prolongPipe(r, w *os.File) {
}

func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	return nil, nil, fmt.Errorf("CreateMemMappedFile is not implemented")
}

func CloseMemMappedFile(f *os.File, mem []byte) error {
	return fmt.Errorf("CloseMemMappedFile is not implemented")
}

func LongPipe() (io.ReadCloser, io.WriteCloser, error) {
	return nil, nil, fmt.Errorf("LongPipe is not implemented")
}

func ProcessExitStatus(ps *os.ProcessState) int {
	return ps.Sys().(syscall.WaitStatus).ExitStatus()
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
