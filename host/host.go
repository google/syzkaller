// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/syzkaller/sys"
)

// DetectSupportedSyscalls returns list on supported syscalls on host.
func DetectSupportedSyscalls() (map[*sys.Call]bool, error) {
	// There are 3 possible strategies:
	// 1. Executes all syscalls with presumably invalid arguments and check for ENOSYS.
	//    But not all syscalls are safe to execute. For example, pause will hang,
	//    while setpgrp will push the process into own process group.
	// 2. Check presence of /sys/kernel/debug/tracing/events/syscalls/sys_enter_* files.
	//    This requires root and CONFIG_FTRACE_SYSCALLS. Also it lies for some syscalls.
	//    For example, on x86_64 it says that sendfile is not present (only sendfile64).
	// 3. Check sys_syscallname in /proc/kallsyms.
	//    Requires CONFIG_KALLSYMS. Seems to be the most reliable. That's what we use here.

	kallsyms, _ := ioutil.ReadFile("/proc/kallsyms")
	supported := make(map[*sys.Call]bool)
	for _, c := range sys.Calls {
		if isSupported(kallsyms, c) {
			supported[c] = true
		}
	}
	return supported, nil
}

func isSupported(kallsyms []byte, c *sys.Call) bool {
	if c.NR == -1 {
		return false // don't even have a syscall number
	}
	if strings.HasPrefix(c.CallName, "syz_") {
		return isSupportedSyzkall(c)
	}
	if strings.HasPrefix(c.Name, "socket$") {
		return isSupportedSocket(c)
	}
	if strings.HasPrefix(c.Name, "open$") {
		return isSupportedOpen(c)
	}
	if strings.HasPrefix(c.Name, "openat$") {
		return isSupportedOpenAt(c)
	}
	if len(kallsyms) == 0 {
		return true
	}
	return bytes.Index(kallsyms, []byte(" T sys_"+c.CallName+"\n")) != -1
}

func isSupportedSyzkall(c *sys.Call) bool {
	switch c.CallName {
	case "syz_test":
		return false
	case "syz_open_dev":
		if _, ok := c.Args[0].(*sys.ConstType); ok {
			// This is for syz_open_dev$char/block.
			// They are currently commented out, but in case one enables them.
			return true
		}
		fname, ok := extractStringConst(c.Args[0])
		if !ok {
			panic("first open arg is not a pointer to string const")
		}
		if syscall.Getuid() != 0 {
			return false
		}
		var check func(dev string) bool
		check = func(dev string) bool {
			if !strings.Contains(dev, "#") {
				_, err := os.Stat(dev)
				return err == nil
			}
			for i := 0; i < 10; i++ {
				if check(strings.Replace(dev, "#", strconv.Itoa(i), 1)) {
					return true
				}
			}
			return false
		}
		return check(fname)
	case "syz_open_pts":
		return true
	case "syz_fuse_mount":
		_, err := os.Stat("/dev/fuse")
		return err == nil
	case "syz_fuseblk_mount":
		_, err := os.Stat("/dev/fuse")
		return err == nil && syscall.Getuid() == 0
	case "syz_emit_ethernet":
		fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
		if err == nil {
			syscall.Close(fd)
		}
		return err == nil && syscall.Getuid() == 0
	case "syz_kvm_setup_cpu":
		switch c.Name {
		case "syz_kvm_setup_cpu$x86":
			return runtime.GOARCH == "amd64" || runtime.GOARCH == "386"
		case "syz_kvm_setup_cpu$arm64":
			return runtime.GOARCH == "arm64"
		}
	}
	panic("unknown syzkall: " + c.Name)
}

func isSupportedSocket(c *sys.Call) bool {
	af, ok := c.Args[0].(*sys.ConstType)
	if !ok {
		println(c.Name)
		panic("socket family is not const")
	}
	fd, err := syscall.Socket(int(af.Val), 0, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	return err != syscall.ENOSYS && err != syscall.EAFNOSUPPORT
}

func isSupportedOpen(c *sys.Call) bool {
	fname, ok := extractStringConst(c.Args[0])
	if !ok {
		return true
	}
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	return err == nil
}

func isSupportedOpenAt(c *sys.Call) bool {
	fname, ok := extractStringConst(c.Args[1])
	if !ok {
		return true
	}
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	return err == nil
}

func extractStringConst(typ sys.Type) (string, bool) {
	ptr, ok := typ.(*sys.PtrType)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	str, ok := ptr.Type.(*sys.BufferType)
	if !ok || str.Kind != sys.BufferString || len(str.Values) != 1 {
		return "", false
	}
	v := str.Values[0]
	v = v[:len(v)-1] // string terminating \x00
	return v, true
}
