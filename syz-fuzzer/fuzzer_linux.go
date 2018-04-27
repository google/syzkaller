// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/linux"
)

func kmemleakInit(enable bool) {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		if !enable {
			return
		}
		log.Fatalf("BUG: /sys/kernel/debug/kmemleak is missing (%v). Enable CONFIG_KMEMLEAK and mount debugfs.", err)
	}
	defer syscall.Close(fd)
	what := "scan=off"
	if !enable {
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
	start := time.Now()
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
	// Account for MSECS_MIN_AGE
	// (1 second less because scanning will take at least a second).
	for time.Since(start) < 4*time.Second {
		time.Sleep(time.Second)
	}
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
			nleaks := 0
			for kmemleakBuf = kmemleakBuf[:n]; len(kmemleakBuf) != 0; {
				end := bytes.Index(kmemleakBuf[1:], []byte("unreferenced object"))
				if end != -1 {
					end++
				} else {
					end = len(kmemleakBuf)
				}
				report := kmemleakBuf[:end]
				kmemleakBuf = kmemleakBuf[end:]
				if kmemleakIgnore(report) {
					continue
				}
				// BUG in output should be recognized by manager.
				log.Logf(0, "BUG: memory leak\n%s\n", report)
				nleaks++
			}
			if nleaks != 0 {
				os.Exit(1)
			}
		}

	}
	if _, err := syscall.Write(fd, []byte("clear")); err != nil {
		panic(err)
	}
}

func kmemleakIgnore(report []byte) bool {
	// kmemleak has a bunch of false positives (at least what looks like
	// false positives at first glance). So we are conservative with what we report.
	// First, we filter out any allocations that don't come from executor processes.
	// Second, we ignore a bunch of functions entirely.
	// Ideally, someone should debug/fix all these cases and remove ignores.
	if !bytes.Contains(report, []byte(`comm "syz-executor`)) {
		return true
	}
	for _, ignore := range []string{
		" copy_process",
		" do_execveat_common",
		" __ext4_",
		" get_empty_filp",
		" do_filp_open",
		" new_inode",
	} {
		if bytes.Contains(report, []byte(ignore)) {
			return true
		}
	}
	return false
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
	// Trigger host target lazy initialization, it will fill linux.KCOV_INIT_TRACE.
	// It's all wrong and needs to be refactored.
	if _, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH); err != nil {
		log.Fatalf("%v", err)
	}
	kcov = true
	coverSize := uintptr(64 << 10)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_INIT_TRACE, coverSize)
	if errno != 0 {
		log.Logf(1, "KCOV_CHECK: KCOV_INIT_TRACE = %v", errno)
		return
	}
	mem, err := syscall.Mmap(fd, 0, int(coverSize*unsafe.Sizeof(uintptr(0))),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		log.Logf(1, "KCOV_CHECK: mmap = %v", err)
		return
	}
	defer syscall.Munmap(mem)
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), linux.KCOV_ENABLE, linux.KCOV_TRACE_CMP)
	if errno != 0 {
		log.Logf(1, "KCOV_CHECK: KCOV_ENABLE = %v", errno)
		return
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_DISABLE, 0)
	comps = true
	return
}
