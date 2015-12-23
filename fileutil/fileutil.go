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
	"sync"
	"syscall"
)

var copyMu sync.Mutex

// CopyFile copies oldFile to newFile, potentially serializing with other
// file copies (for large files).
func CopyFile(oldFile, newFile string, serial bool) error {
	if serial {
		copyMu.Lock()
		defer copyMu.Unlock()
	}

	oldf, err := os.Open(oldFile)
	if err != nil {
		return err
	}
	defer oldf.Close()
	newf, err := os.Create(newFile)
	if err != nil {
		return err
	}
	defer newf.Close()
	_, err = io.Copy(newf, oldf)
	if err != nil {
		return err
	}
	return nil
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
func ProcessTempDir(where string) (string, int, error) {
	for i := 0; i < 1e4; i++ {
		path := filepath.Join(where, fmt.Sprintf("instance-%v", i))
		pidfile := filepath.Join(path, ".pid")
		err := os.Mkdir(path, 0700)
		if os.IsExist(err) {
			// Try to clean up.
			data, err := ioutil.ReadFile(pidfile)
			if err == nil {
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
			return "", 0, err
		}
		if err := ioutil.WriteFile(pidfile, []byte(strconv.Itoa(syscall.Getpid())), 0600); err != nil {
			return "", 0, err
		}
		return path, i, nil
	}
	return "", 0, fmt.Errorf("too many live instances")
}
