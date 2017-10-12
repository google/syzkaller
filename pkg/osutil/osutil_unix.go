// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build freebsd,!appengine linux,!appengine darwin,!appengine

package osutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
)

// ProcessTempDir creates a new temp dir in where and returns its path and an unique index.
// It also cleans up old, unused temp dirs after dead processes.
func ProcessTempDir(where string) (string, error) {
	lk := filepath.Join(where, "instance-lock")
	lkf, err := syscall.Open(lk, syscall.O_RDWR|syscall.O_CREAT, DefaultFilePerm)
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
		err := os.Mkdir(path, DefaultDirPerm)
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
		if err := WriteFile(pidfile, []byte(strconv.Itoa(syscall.Getpid()))); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("too many live instances")
}

// HandleInterrupts closes shutdown chan on first SIGINT
// (expecting that the program will gracefully shutdown and exit)
// and terminates the process on third SIGINT.
func HandleInterrupts(shutdown chan struct{}) {
	go func() {
		c := make(chan os.Signal, 3)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
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

func LongPipe() (io.ReadCloser, io.WriteCloser, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	prolongPipe(r, w)
	return r, w, err
}
