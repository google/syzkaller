// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	setPdeathsig(cmd, true)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %v %+v: %w", cmd.Path, cmd.Args, err)
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
			text = fmt.Sprintf("timedout after %v %q", timeout, cmd.Args)
		}
		exitCode := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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

// CommandContext is similar to os/exec.CommandContext, but also sets PDEATHSIG to SIGKILL on linux,
// i.e. the child will be killed immediately.
func CommandContext(ctx context.Context, bin string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bin, args...)
	setPdeathsig(cmd, true)
	return cmd
}

// Command is similar to os/exec.Command, but also sets PDEATHSIG to SIGKILL on linux,
// i.e. the child will be killed immediately.
func Command(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	setPdeathsig(cmd, true)
	return cmd
}

// Command is similar to os/exec.Command, but also sets PDEATHSIG to SIGTERM on linux,
// i.e. the child has a chance to exit gracefully. This may be important when running
// e.g. syz-manager. If it is killed immediately, it can leak GCE instances.
func GraciousCommand(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	setPdeathsig(cmd, false)
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
	var verboseError *VerboseError
	switch {
	case errors.As(err, &verboseError):
		verboseError.Title = fmt.Sprintf("%v: %v", ctx, verboseError.Title)
		return verboseError
	default:
		return fmt.Errorf("%v: %w", ctx, err)
	}
}

func IsDir(name string) bool {
	fileInfo, err := os.Stat(name)
	return err == nil && fileInfo.IsDir()
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
		return fmt.Errorf("%v can't be opened (%w)", name, err)
	}
	f.Close()
	return nil
}

// IsWritable checks if the file can be written.
func IsWritable(name string) error {
	f, err := os.OpenFile(name, os.O_WRONLY, DefaultFilePerm)
	if err != nil {
		return fmt.Errorf("%v can't be written (%w)", name, err)
	}
	f.Close()
	return nil
}

// FilesExist returns true if all files exist in dir.
// Files are assumed to be relative names in slash notation.
func FilesExist(dir string, files map[string]bool) bool {
	for pattern, required := range files {
		if !required {
			continue
		}
		files, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
		if err != nil || len(files) == 0 {
			return false
		}
	}
	return true
}

// CopyFiles copies files from srcDir to dstDir as atomically as possible.
// Files are assumed to be relative glob patterns in slash notation in srcDir.
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
	if err := foreachPatternFile(srcDir, tmpDir, files, CopyFile); err != nil {
		return err
	}
	if err := os.RemoveAll(dstDir); err != nil {
		return err
	}
	return os.Rename(tmpDir, dstDir)
}

func foreachPatternFile(srcDir, dstDir string, files map[string]bool, fn func(src, dst string) error) error {
	srcDir = filepath.Clean(srcDir)
	dstDir = filepath.Clean(dstDir)
	for pattern, required := range files {
		files, err := filepath.Glob(filepath.Join(srcDir, filepath.FromSlash(pattern)))
		if err != nil {
			return err
		}
		if len(files) == 0 {
			if !required {
				continue
			}
			return fmt.Errorf("file %v does not exist", pattern)
		}
		for _, file := range files {
			if !strings.HasPrefix(file, srcDir) {
				return fmt.Errorf("file %q matched from %q in %q doesn't have src prefix", file, pattern, srcDir)
			}
			dst := filepath.Join(dstDir, strings.TrimPrefix(file, srcDir))
			if err := MkdirAll(filepath.Dir(dst)); err != nil {
				return err
			}
			if err := fn(file, dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func CopyDirRecursively(srcDir, dstDir string) error {
	if err := MkdirAll(dstDir); err != nil {
		return err
	}
	files, err := os.ReadDir(srcDir)
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
	return foreachPatternFile(srcDir, dstDir, files, os.Link)
}

func MkdirAll(dir string) error {
	return os.MkdirAll(dir, DefaultDirPerm)
}

func WriteFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, DefaultFilePerm)
}

func WriteGzipStream(filename string, reader io.Reader) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	_, err = io.Copy(gz, reader)
	return err
}

func WriteExecFile(filename string, data []byte) error {
	os.Remove(filename)
	return os.WriteFile(filename, data, DefaultExecPerm)
}

// TempFile creates a unique temp filename.
// Note: the file already exists when the function returns.
func TempFile(prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
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

var (
	wd     string
	wdOnce sync.Once
)

func Abs(path string) string {
	wdOnce.Do(func() {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			panic(fmt.Sprintf("failed to get wd: %v", err))
		}
	})
	if wd1, err := os.Getwd(); err == nil && wd1 != wd {
		panic(fmt.Sprintf("wd changed: %q -> %q", wd, wd1))
	}
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(wd, path)
}
