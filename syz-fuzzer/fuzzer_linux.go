// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/linux"
)

func kmemleakInit() {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		if *flagLeak {
			log.Fatalf("BUG: /sys/kernel/debug/kmemleak is missing (%v). Enable CONFIG_KMEMLEAK and mount debugfs.", err)
		} else {
			return
		}
	}
	defer syscall.Close(fd)
	what := "scan=off"
	if !*flagLeak {
		what = "off"
	}
	if _, err := syscall.Write(fd, []byte(what)); err != nil {
		// kmemleak returns EBUSY when kmemleak is already turned off.
		if err != syscall.EBUSY {
			panic(err)
		}
	}
}

var kmemleakBuf []byte

func kmemleakScan(report bool) {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	// Kmemleak has false positives. To mitigate most of them, it checksums
	// potentially leaked objects, and reports them only on the next scan
	// iff the checksum does not change. Because of that we do the following
	// intricate dance:
	// Scan, sleep, scan again. At this point we can get some leaks.
	// If there are leaks, we sleep and scan again, this can remove
	// false leaks. Then, read kmemleak again. If we get leaks now, then
	// hopefully these are true positives during the previous testing cycle.
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		panic(err)
	}
	if report {
		if kmemleakBuf == nil {
			kmemleakBuf = make([]byte, 128<<10)
		}
		n, err := syscall.Read(fd, kmemleakBuf)
		if err != nil {
			panic(err)
		}
		if n != 0 {
			time.Sleep(time.Second)
			if _, err := syscall.Write(fd, []byte("scan")); err != nil {
				panic(err)
			}
			n, err := syscall.Read(fd, kmemleakBuf)
			if err != nil {
				panic(err)
			}
			if n != 0 {
				// BUG in output should be recognized by manager.
				log.Logf(0, "BUG: memory leak:\n%s\n", kmemleakBuf[:n])
			}
		}
	}
	if _, err := syscall.Write(fd, []byte("clear")); err != nil {
		panic(err)
	}
}

// Checks if the KCOV device supports comparisons.
// Returns a pair of bools:
//		First  - is the kcov device present in the system.
//		Second - is the kcov device supporting comparisons.
func checkCompsSupported() (kcov, comps bool) {
	// TODO(dvyukov): this should run under target arch.
	// E.g. KCOV ioctls were initially not supported on 386 (missing compat_ioctl),
	// and a 386 executor won't be able to use them, but an amd64 fuzzer will be.
	fd, err := syscall.Open("/sys/kernel/debug/kcov", syscall.O_RDWR, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	kcov = true
	coverSize := uintptr(64 << 10)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_INIT_TRACE, coverSize)
	if errno != 0 {
		log.Logf(1, "KCOV_CHECK: KCOV_INIT_TRACE = %v", errno)
		return
	}
	_, err = syscall.Mmap(fd, 0, int(coverSize*8),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		log.Logf(1, "KCOV_CHECK: mmap = %v", err)
		return
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), linux.KCOV_ENABLE, linux.KCOV_TRACE_CMP)
	log.Logf(1, "KCOV_CHECK: KCOV_ENABLE = %v", errno)
	comps = errno == 0
	return
}
