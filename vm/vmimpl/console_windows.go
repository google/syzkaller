// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//go:build windows

package vmimpl

import (
	"fmt"
	"io"
	"os/exec"
	"sync"

	_ "github.com/google/syzkaller/pkg/osutil"
)

// Merely to fix build.
const (
	unixCBAUD     = 0
	unixCRTSCTS   = 0
	syscallTCGETS = 0
	syscallTCSETS = 0
)

func OpenConsole(con string) (rc io.ReadCloser, err error) {
	return nil, fmt.Errorf("failed to get console termios on Windows: %v", err)
}

type tty struct {
	mu sync.Mutex
	fd int
}

// OpenRemoteKernelLog accesses to the host where Android VM runs on, not Android VM itself.
// The host stores all kernel outputs of Android VM so in case of crashes nothing will be lost.
func OpenRemoteKernelLog(ip, console string) (rc io.ReadCloser, err error) {
	return nil, fmt.Errorf("failed to connect to console server on Windows: %v", err)
}

// Open dmesg remotely.
func OpenRemoteConsole(bin string, args ...string) (rc io.ReadCloser, err error) {
	return nil, fmt.Errorf("failed to start adb: %v", err)
}

// OpenAdbConsole provides fallback console output using 'adb shell dmesg -w'.
func OpenAdbConsole(bin, dev string) (rc io.ReadCloser, err error) {
	return OpenRemoteConsole(bin, "-s", dev, "shell")
}

type remoteCon struct {
	closeMu sync.Mutex
	readMu  sync.Mutex
	cmd     *exec.Cmd
	rpipe   io.ReadCloser
}

func (t *remoteCon) Read(buf []byte) (int, error) {
	t.readMu.Lock()
	n, err := t.rpipe.Read(buf)
	t.readMu.Unlock()
	return n, err
}

func (t *remoteCon) Close() error {
	t.closeMu.Lock()
	cmd := t.cmd
	t.cmd = nil
	t.closeMu.Unlock()
	if cmd == nil {
		return nil
	}

	cmd.Process.Kill()

	t.readMu.Lock()
	t.rpipe.Close()
	t.readMu.Unlock()

	cmd.Process.Wait()
	return nil
}
