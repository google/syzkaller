// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fileutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// CopyFile atomically copies oldFile to newFile preserving permissions and modification time.
func CopyFile(oldFile, newFile string) error {
	oldf, err := os.Open(oldFile)
	if err != nil {
		return err
	}
	defer oldf.Close()
	stat, err := oldf.Stat()
	if err != nil {
		return err
	}
	tmpFile := newFile + ".tmp"
	newf, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stat.Mode()&os.ModePerm)
	if err != nil {
		return err
	}
	defer newf.Close()
	_, err = io.Copy(newf, oldf)
	if err != nil {
		return err
	}
	if err := newf.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmpFile, stat.ModTime(), stat.ModTime()); err != nil {
		return err
	}
	return os.Rename(tmpFile, newFile)
}

// WriteTempFile writes data to a temp file and returns its name.
func WriteTempFile(data []byte) (string, error) {
	f, err := ioutil.TempFile("", "syzkaller")
	if err != nil {
		return "", fmt.Errorf("failed to create a temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write a temp file: %v", err)
	}
	f.Close()
	return f.Name(), nil
}

// ProcessTempDir creates a new temp dir in where and returns its path and an unique index.
// It also cleans up old, unused temp dirs after dead processes.
func ProcessTempDir(where string) (string, error) {
	lk := filepath.Join(where, "instance-lock")
	lkf, err := syscall.Open(lk, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		return "", err
	}
	defer syscall.Close(lkf)
	if err := syscall.Flock(lkf, syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer syscall.Flock(lkf, syscall.LOCK_UN)

	for i := 0; i < 1e3; i++ {
		path := filepath.Join(where, fmt.Sprintf("instance-%v", i))
		pidfile := filepath.Join(path, ".pid")
		err := os.Mkdir(path, 0700)
		if os.IsExist(err) {
			// Try to clean up.
			data, err := ioutil.ReadFile(pidfile)
			if err == nil && len(data) > 0 {
				pid, err := strconv.Atoi(string(data))
				if err == nil && pid > 1 {
					if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
						if os.Remove(pidfile) == nil {
							if os.RemoveAll(path) == nil {
								i--
								continue
							}
						}
					}
				}
			}
			// If err != nil, assume that the pid file is not created yet.
			continue
		}
		if err != nil {
			return "", err
		}
		if err := ioutil.WriteFile(pidfile, []byte(strconv.Itoa(syscall.Getpid())), 0600); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("too many live instances")
}
