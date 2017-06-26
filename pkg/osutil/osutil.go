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

	"github.com/google/syzkaller/pkg/fileutil"
)

const (
	DefaultDirPerm  = 0755
	DefaultFilePerm = 0644
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
	prolongPipe(r, w)
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

// FilesExist returns true if all files exist in dir.
// Files are assumed to be relative names in slash notation.
func FilesExist(dir string, files []string) bool {
	for _, f := range files {
		if !IsExist(filepath.Join(dir, filepath.FromSlash(f))) {
			return false
		}
	}
	return true
}

// CopyFiles copies files from srcDir to dstDir as atomically as possible.
// Files are assumed to be relative names in slash notation.
// All other files in dstDir are removed.
func CopyFiles(srcDir, dstDir string, files []string) error {
	// Linux does not support atomic dir replace, so we copy to tmp dir first.
	// Then remove dst dir and rename tmp to dst (as atomic as can get on Linux).
	tmpDir := dstDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}
	if err := os.MkdirAll(tmpDir, DefaultDirPerm); err != nil {
		return err
	}
	for _, f := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		dst := filepath.Join(tmpDir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(dst), DefaultDirPerm); err != nil {
			return err
		}
		if err := fileutil.CopyFile(src, dst); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(dstDir); err != nil {
		return err
	}
	return os.Rename(tmpDir, dstDir)
}

// LinkFiles creates hard links for files from dstDir to srcDir.
// Files are assumed to be relative names in slash notation.
// All other files in dstDir are removed.
func LinkFiles(srcDir, dstDir string, files []string) error {
	if err := os.RemoveAll(dstDir); err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, DefaultDirPerm); err != nil {
		return err
	}
	for _, f := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		dst := filepath.Join(dstDir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(dst), DefaultDirPerm); err != nil {
			return err
		}
		if err := os.Link(src, dst); err != nil {
			return err
		}
	}
	return nil
}
