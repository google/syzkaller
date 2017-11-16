// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	DefaultDirPerm  = 0755
	DefaultFilePerm = 0644
	DefaultExecPerm = 0755
)

// RunCmd runs "bin args..." in dir with timeout and returns its output.
func RunCmd(timeout time.Duration, dir, bin string, args ...string) ([]byte, error) {
	cmd := Command(bin, args...)
	cmd.Dir = dir
	return Run(timeout, cmd)
}

// Run runs cmd with the specified timeout.
// Returns combined output. If the command fails, err includes output.
func Run(timeout time.Duration, cmd *exec.Cmd) ([]byte, error) {
	output := new(bytes.Buffer)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %v %+v: %v", cmd.Path, cmd.Args, err)
	}
	done := make(chan bool)
	timer := time.NewTimer(timeout)
	go func() {
		select {
		case <-timer.C:
			cmd.Process.Kill()
		case <-done:
			timer.Stop()
		}
	}()
	defer close(done)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to run %v %+v: %v\n%v",
			cmd.Path, cmd.Args, err, output.String())
	}
	return output.Bytes(), nil
}

// Command is similar to os/exec.Command, but also sets PDEATHSIG on linux.
func Command(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	setPdeathsig(cmd)
	return cmd
}

// IsExist returns true if the file name exists.
func IsExist(name string) bool {
	_, err := os.Stat(name)
	return err == nil
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
	if err := MkdirAll(tmpDir); err != nil {
		return err
	}
	for _, f := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		dst := filepath.Join(tmpDir, filepath.FromSlash(f))
		if err := MkdirAll(filepath.Dir(dst)); err != nil {
			return err
		}
		if err := CopyFile(src, dst); err != nil {
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
	if err := MkdirAll(dstDir); err != nil {
		return err
	}
	for _, f := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		dst := filepath.Join(dstDir, filepath.FromSlash(f))
		if err := MkdirAll(filepath.Dir(dst)); err != nil {
			return err
		}
		if err := os.Link(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func MkdirAll(dir string) error {
	return os.MkdirAll(dir, DefaultDirPerm)
}

func WriteFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, DefaultFilePerm)
}

func WriteExecFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, DefaultExecPerm)
}

// Return all files in a directory.
func ListDir(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
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
