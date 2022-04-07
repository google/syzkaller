// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build freebsd || netbsd || openbsd || darwin
// +build freebsd netbsd openbsd darwin

package osutil

import (
	"fmt"
	"io/ioutil"
	"os"
)

func CreateSharedMemFile(size int) (f *os.File, err error) {
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}
	f.Close()
	fname := f.Name()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, DefaultFilePerm)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fname)
	}
	return
}

func CloseSharedMemFile(f *os.File) error {
	err1 := f.Close()
	err2 := os.Remove(f.Name())
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}
