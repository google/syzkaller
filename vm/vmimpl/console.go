// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"

	"github.com/google/syzkaller/pkg/osutil"
)

// Tested on Suzy-Q and BeagleBone.
func OpenConsole(con string) (rc io.ReadCloser, err error) {
	fd, err := syscall.Open(con, syscall.O_RDONLY|syscall.O_NOCTTY|syscall.O_SYNC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open console file: %v", err)
	}
	defer func() {
		if fd != -1 {
			syscall.Close(fd)
		}
	}()

	// Shell out to stty to modify the baudrate of the file descriptor
	// that we have opened.
	fd_name := fmt.Sprintf("/dev/fd/%v", int(fd))
	cmd := exec.Command("stty", "-f", fd_name, "115200")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("stty %v could not start: %v", fd_name, err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("stty %v exited with error code: %v", fd_name, err)
	}

	tmp := fd
	fd = -1
	return &tty{fd: tmp}, nil
}

type tty struct {
	mu sync.Mutex
	fd int
}

func (t *tty) Read(buf []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fd == -1 {
		return 0, io.EOF
	}
	n, err := syscall.Read(t.fd, buf)
	if n < 0 {
		n = 0
	}
	return n, err
}

func (t *tty) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fd != -1 {
		syscall.Close(t.fd)
		t.fd = -1
	}
	return nil
}

// OpenAdbConsole provides fallback console output using 'adb shell dmesg -w'.
func OpenAdbConsole(bin, dev string) (rc io.ReadCloser, err error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-s", dev, "shell", "dmesg -w")
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, fmt.Errorf("failed to start adb: %v", err)
	}
	wpipe.Close()
	con := &adbCon{
		cmd:   cmd,
		rpipe: rpipe,
	}
	return con, err
}

type adbCon struct {
	closeMu sync.Mutex
	readMu  sync.Mutex
	cmd     *exec.Cmd
	rpipe   io.ReadCloser
}

func (t *adbCon) Read(buf []byte) (int, error) {
	t.readMu.Lock()
	n, err := t.rpipe.Read(buf)
	t.readMu.Unlock()
	return n, err
}

func (t *adbCon) Close() error {
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
