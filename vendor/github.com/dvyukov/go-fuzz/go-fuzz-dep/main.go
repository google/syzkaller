// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz
// +build !gofuzz_libfuzzer

package gofuzzdep

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
)

func Main(fns []func([]byte) int) {
	mem, inFD, outFD := setupCommFile()
	CoverTab = (*[CoverSize]byte)(unsafe.Pointer(&mem[0]))
	input := mem[CoverSize : CoverSize+MaxInputSize]
	sonarRegion = mem[CoverSize+MaxInputSize:]
	runtime.GOMAXPROCS(1) // makes coverage more deterministic, we parallelize on higher level
	for {
		fnidx, n := read(inFD)
		if n > uint64(len(input)) {
			println("invalid input length")
			syscall.Exit(1)
		}
		for i := range CoverTab {
			CoverTab[i] = 0
		}
		atomic.StoreUint32(&sonarPos, 0)
		t0 := time.Now()
		res := fns[fnidx](input[:n:n])
		ns := time.Since(t0)
		write(outFD, uint64(res), uint64(ns), uint64(atomic.LoadUint32(&sonarPos)))
	}
}

// read reads little-endian-encoded uint8+uint64 from fd.
func read(fd FD) (uint8, uint64) {
	rd := 0
	var buf [9]byte
	for rd != len(buf) {
		n, err := fd.read(buf[rd:])
		if err == syscall.EINTR {
			continue
		}
		if n == 0 {
			syscall.Exit(1)
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		rd += n
	}
	return buf[0], deserialize64(buf[1:])
}

// write writes little-endian-encoded vals... to fd.
func write(fd FD, vals ...uint64) {
	var tmp [3 * 8]byte
	buf := tmp[:len(vals)*8]
	for i, v := range vals {
		serialize64(buf[i*8:], v)
	}
	wr := 0
	for wr != len(buf) {
		n, err := fd.write(buf[wr:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		wr += n
	}
}

// writeStr writes strings s to fd.
func writeStr(fd FD, s string) {
	buf := []byte(s)
	wr := 0
	for wr != len(buf) {
		n, err := fd.write(buf[wr:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			println("failed to read fd =", fd, "errno =", err.(syscall.Errno))
			syscall.Exit(1)
		}
		wr += n
	}
}
