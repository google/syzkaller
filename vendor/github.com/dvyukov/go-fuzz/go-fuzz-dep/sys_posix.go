// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin linux freebsd dragonfly openbsd netbsd
// +build gofuzz

package gofuzzdep

import (
	"syscall"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
)

type FD int

func setupCommFile() ([]byte, FD, FD) {
	mem, err := syscall.Mmap(3, 0, CoverSize+MaxInputSize+SonarRegionSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		println("failed to mmap fd = 3 errno =", err.(syscall.Errno))
		syscall.Exit(1)
	}
	return mem, 4, 5
}

func (fd FD) read(buf []byte) (int, error) {
	return syscall.Read(int(fd), buf)
}

func (fd FD) write(buf []byte) (int, error) {
	return syscall.Write(int(fd), buf)
}
