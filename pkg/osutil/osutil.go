// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// RunCmd runs "bin args..." in dir with timeout and returns its output.
func RunCmd(timeout time.Duration, dir, bin string, args ...string) ([]byte, error) {
	output := new(bytes.Buffer)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %v %+v: %v", bin, args, err)
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Hour):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	defer close(done)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to run %v %+v: %v\n%v", bin, args, err, output.String())
	}
	return output.Bytes(), nil
}

func LongPipe() (io.ReadCloser, io.WriteCloser, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
	return r, w, err
}

var wd string

func init() {
	var err error
	wd, err = os.Getwd()
	if err != nil {
		panic(fmt.Sprintf("failed to get wd: %v", err))
	}
}

func Abs(path string) string {
	if wd1, err := os.Getwd(); err == nil && wd1 != wd {
		panic("don't mess with wd in a concurrent program")
	}
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(wd, path)
}

// IsExist returns true if the file name exists.
func IsExist(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// HandleInterrupts closes shutdown chan on first SIGINT
// (expecting that the program will gracefully shutdown and exit)
// and terminates the process on third SIGINT.
func HandleInterrupts(shutdown chan struct{}) {
	go func() {
		c := make(chan os.Signal, 3)
		signal.Notify(c, syscall.SIGINT)
		<-c
		close(shutdown)
		fmt.Fprint(os.Stderr, "SIGINT: shutting down...\n")
		<-c
		fmt.Fprint(os.Stderr, "SIGINT: shutting down harder...\n")
		<-c
		fmt.Fprint(os.Stderr, "SIGINT: terminating\n")
		os.Exit(int(syscall.SIGINT))
	}()
}
