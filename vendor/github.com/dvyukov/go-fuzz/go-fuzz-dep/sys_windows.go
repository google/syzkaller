// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package gofuzzdep

import (
	"syscall"
	"unsafe"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
)

// Can't import reflect because of import cycles.
type sliceHeader struct {
	addr uintptr
	l, c int
}

type FD syscall.Handle

func setupCommFile() ([]byte, FD, FD) {
	const (
		size                = CoverSize + MaxInputSize + SonarRegionSize
		FILE_MAP_ALL_ACCESS = 0xF001F
	)
	mapping := readEnvParam("GO_FUZZ_COMM_FD")
	addr, err := syscall.MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size)
	if err != nil {
		println("failed to mmap comm file:", err.Error())
		syscall.Exit(1)
	}
	hdr := sliceHeader{addr, size, size}
	mem := *(*[]byte)(unsafe.Pointer(&hdr))
	in := FD(readEnvParam("GO_FUZZ_IN_FD"))
	out := FD(readEnvParam("GO_FUZZ_OUT_FD"))
	return mem, in, out
}

func readEnvParam(name string) syscall.Handle {
	v, _ := syscall.Getenv(name)
	var x uintptr
	for i := 0; i < len(v); i++ {
		x = x*10 + uintptr(v[i]-'0')
	}
	return syscall.Handle(x)
}

func (fd FD) read(buf []byte) (int, error) {
	return syscall.Read(syscall.Handle(fd), buf)
}

func (fd FD) write(buf []byte) (int, error) {
	return syscall.Write(syscall.Handle(fd), buf)
}
