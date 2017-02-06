// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/vm"
	. "golang.org/x/sys/unix"
)

// Tested on Suzy-Q and BeagleBone.
func openConsole(con string) (rc io.ReadCloser, err error) {
	fd, err := syscall.Open(con, syscall.O_RDONLY|syscall.O_NOCTTY|syscall.O_SYNC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open console file: %v", err)
	}
	defer func() {
		if fd != -1 {
			syscall.Close(fd)
		}
	}()
	var term Termios
	if _, _, errno := syscall.Syscall(SYS_IOCTL, uintptr(fd), TCGETS2, uintptr(unsafe.Pointer(&term))); errno != 0 {
		return nil, fmt.Errorf("failed to get console termios: %v", errno)
	}
	// no parity bit, only need 1 stop bit, no hardware flowcontrol
	term.Cflag &^= CBAUD | CSIZE | PARENB | CSTOPB | CRTSCTS
	// ignore modem controls
	term.Cflag |= B115200 | CS8 | CLOCAL | CREAD
	// setup for non-canonical mode
	term.Iflag &^= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON
	term.Lflag &^= ECHO | ECHONL | ICANON | ISIG | IEXTEN
	term.Oflag &^= OPOST
	term.Cc[VMIN] = 0
	term.Cc[VTIME] = 10 // 1 second timeout
	if _, _, errno := syscall.Syscall(SYS_IOCTL, uintptr(fd), TCSETS2, uintptr(unsafe.Pointer(&term))); errno != 0 {
		return nil, fmt.Errorf("failed to get console termios: %v", errno)
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

// openAdbConsole provides fallback console output using 'adb shell dmesg -w'.
func openAdbConsole(bin, dev string) (rc io.ReadCloser, err error) {
	rpipe, wpipe, err := vm.LongPipe()
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
