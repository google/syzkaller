// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/sys/unix"
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
	var term unix.Termios
	_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), syscallTCGETS, uintptr(unsafe.Pointer(&term)))
	if errno != 0 {
		return nil, fmt.Errorf("failed to get console termios: %v", errno)
	}
	// no parity bit, only need 1 stop bit, no hardware flowcontrol
	term.Cflag &^= unixCBAUD | unix.CSIZE | unix.PARENB | unix.CSTOPB | unixCRTSCTS
	// ignore modem controls
	term.Cflag |= unix.B115200 | unix.CS8 | unix.CLOCAL | unix.CREAD
	// setup for non-canonical mode
	term.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR |
		unix.IGNCR | unix.ICRNL | unix.IXON
	term.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	term.Oflag &^= unix.OPOST
	term.Cc[unix.VMIN] = 0
	term.Cc[unix.VTIME] = 10 // 1 second timeout
	_, _, errno = syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), syscallTCSETS, uintptr(unsafe.Pointer(&term)))
	if errno != 0 {
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

// Open dmesg remotely
func OpenRemoteConsole(bin string, args ...string) (rc io.ReadCloser, err error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	args = append(args, "dmesg -w")
	cmd := osutil.Command(bin, args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, fmt.Errorf("failed to start adb: %v", err)
	}
	wpipe.Close()
	con := &remoteCon{
		cmd:   cmd,
		rpipe: rpipe,
	}
	return con, err
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
