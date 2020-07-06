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
	"syscall"
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
	if cmd.Stdout == nil {
		cmd.Stdout = output
	}
	if cmd.Stderr == nil {
		cmd.Stderr = output
	}
	setPdeathsig(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %v %+v: %v", cmd.Path, cmd.Args, err)
	}
	done := make(chan bool)
	timedout := make(chan bool, 1)
	timer := time.NewTimer(timeout)
	go func() {
		select {
		case <-timer.C:
			timedout <- true
			killPgroup(cmd)
			cmd.Process.Kill()
		case <-done:
			timedout <- false
			timer.Stop()
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		text := fmt.Sprintf("failed to run %q: %v", cmd.Args, err)
		if <-timedout {
			text = fmt.Sprintf("timedout %q", cmd.Args)
		}
		exitCode := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		}
		return output.Bytes(), &VerboseError{
			Title:    text,
			Output:   output.Bytes(),
			ExitCode: exitCode,
		}
	}
	return output.Bytes(), nil
}

// Command is similar to os/exec.Command, but also sets PDEATHSIG on linux.
func Command(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	setPdeathsig(cmd)
	return cmd
}

type VerboseError struct {
	Title    string
	Output   []byte
	ExitCode int
}

func (err *VerboseError) Error() string {
	if len(err.Output) == 0 {
		return err.Title
	}
	return fmt.Sprintf("%v\n%s", err.Title, err.Output)
}

func PrependContext(ctx string, err error) error {
	switch err1 := err.(type) {
	case *VerboseError:
		err1.Title = fmt.Sprintf("%v: %v", ctx, err1.Title)
		return err1
	default:
		return fmt.Errorf("%v: %v", ctx, err)
	}
}

// IsExist returns true if the file name exists.
func IsExist(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// IsAccessible checks if the file can be opened.
func IsAccessible(name string) error {
	if !IsExist(name) {
		return fmt.Errorf("%v does not exist", name)
	}
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("%v can't be opened (%v)", name, err)
	}
	f.Close()
	return nil
}

// FilesExist returns true if all files exist in dir.
// Files are assumed to be relative names in slash notation.
func FilesExist(dir string, files map[string]bool) bool {
	for f, required := range files {
		if !required {
			continue
		}
		if !IsExist(filepath.Join(dir, filepath.FromSlash(f))) {
			return false
		}
	}
	return true
}

// CopyFiles copies files from srcDir to dstDir as atomically as possible.
// Files are assumed to be relative names in slash notation.
// All other files in dstDir are removed.
func CopyFiles(srcDir, dstDir string, files map[string]bool) error {
	// Linux does not support atomic dir replace, so we copy to tmp dir first.
	// Then remove dst dir and rename tmp to dst (as atomic as can get on Linux).
	tmpDir := dstDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}
	if err := MkdirAll(tmpDir); err != nil {
		return err
	}
	for f, required := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		if !required && !IsExist(src) {
			continue
		}
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

func CopyDirRecursively(srcDir, dstDir string) error {
	if err := MkdirAll(dstDir); err != nil {
		return err
	}
	files, err := ioutil.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		src := filepath.Join(srcDir, file.Name())
		dst := filepath.Join(dstDir, file.Name())
		if file.IsDir() {
			if err := CopyDirRecursively(src, dst); err != nil {
				return err
			}
			continue
		}
		if err := CopyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// LinkFiles creates hard links for files from dstDir to srcDir.
// Files are assumed to be relative names in slash notation.
// All other files in dstDir are removed.
func LinkFiles(srcDir, dstDir string, files map[string]bool) error {
	if err := os.RemoveAll(dstDir); err != nil {
		return err
	}
	if err := MkdirAll(dstDir); err != nil {
		return err
	}
	for f, required := range files {
		src := filepath.Join(srcDir, filepath.FromSlash(f))
		if !required && !IsExist(src) {
			continue
		}
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
	os.Remove(filename)
	return ioutil.WriteFile(filename, data, DefaultExecPerm)
}

// TempFile creates a unique temp filename.
// Note: the file already exists when the function returns.
func TempFile(prefix string) (string, error) {
	f, err := ioutil.TempFile("", prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	f.Close()
	return f.Name(), nil
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
