// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func isSupported(c *prog.Syscall, sandbox string) (bool, string) {
	// There are 3 possible strategies for detecting supported syscalls:
	// 1. Executes all syscalls with presumably invalid arguments and check for ENOprog.
	//    But not all syscalls are safe to execute. For example, pause will hang,
	//    while setpgrp will push the process into own process group.
	// 2. Check presence of /sys/kernel/debug/tracing/events/syscalls/sys_enter_* files.
	//    This requires root and CONFIG_FTRACE_SYSCALLS. Also it lies for some syscalls.
	//    For example, on x86_64 it says that sendfile is not present (only sendfile64).
	// 3. Check sys_syscallname in /proc/kallsyms.
	//    Requires CONFIG_KALLSYMS. Seems to be the most reliable. That's what we use here.
	kallsymsOnce.Do(func() {
		kallsyms, _ = ioutil.ReadFile("/proc/kallsyms")
	})
	if strings.HasPrefix(c.CallName, "syz_") {
		return isSupportedSyzkall(sandbox, c)
	}
	if strings.HasPrefix(c.Name, "socket$") {
		return isSupportedSocket(c)
	}
	if strings.HasPrefix(c.Name, "openat$") {
		return isSupportedOpenAt(c)
	}
	if len(kallsyms) == 0 {
		return true, ""
	}
	name := c.CallName
	if newname := kallsymsMap[name]; newname != "" {
		name = newname
	}
	if !bytes.Contains(kallsyms, []byte(" T sys_"+name+"\n")) &&
		!bytes.Contains(kallsyms, []byte(" T ksys_"+name+"\n")) &&
		!bytes.Contains(kallsyms, []byte(" T __ia32_sys_"+name+"\n")) &&
		!bytes.Contains(kallsyms, []byte(" T __x64_sys_"+name+"\n")) {
		return false, fmt.Sprintf("sys_%v is not present in /proc/kallsyms", name)
	}
	return true, ""
}

// Some syscall names diverge in __NR_* consts and kallsyms.
// umount2 is renamed to umount in arch/x86/entry/syscalls/syscall_64.tbl.
// Where umount is renamed to oldumount is unclear.
var (
	kallsyms     []byte
	kallsymsOnce sync.Once
	kallsymsMap  = map[string]string{
		"umount":  "oldumount",
		"umount2": "umount",
	}
)

func isSupportedSyzkall(sandbox string, c *prog.Syscall) (bool, string) {
	switch c.CallName {
	case "syz_open_dev":
		if _, ok := c.Args[0].(*prog.ConstType); ok {
			// This is for syz_open_dev$char/block.
			// They are currently commented out, but in case one enables them.
			return true, ""
		}
		fname, ok := extractStringConst(c.Args[0])
		if !ok {
			panic("first open arg is not a pointer to string const")
		}
		var check func(dev string) bool
		check = func(dev string) bool {
			if !strings.Contains(dev, "#") {
				return osutil.IsExist(dev)
			}
			for i := 0; i < 10; i++ {
				if check(strings.Replace(dev, "#", strconv.Itoa(i), 1)) {
					return true
				}
			}
			return false
		}
		if !check(fname) {
			return false, fmt.Sprintf("file %v does not exist", fname)
		}
		return onlySandboxNoneOrNamespace(sandbox)
	case "syz_open_procfs":
		return true, ""
	case "syz_open_pts":
		return true, ""
	case "syz_fuse_mount":
		if !osutil.IsExist("/dev/fuse") {
			return false, "/dev/fuse does not exist"
		}
		return onlySandboxNoneOrNamespace(sandbox)
	case "syz_fuseblk_mount":
		if !osutil.IsExist("/dev/fuse") {
			return false, "/dev/fuse does not exist"
		}
		return onlySandboxNoneOrNamespace(sandbox)
	case "syz_emit_ethernet", "syz_extract_tcp_res":
		fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
		if err != nil {
			return false, fmt.Sprintf("open(/dev/net/tun) failed: %v", err)
		}
		syscall.Close(fd)
		return true, ""
	case "syz_kvm_setup_cpu":
		switch c.Name {
		case "syz_kvm_setup_cpu$x86":
			if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
				return true, ""
			}
		case "syz_kvm_setup_cpu$arm64":
			if runtime.GOARCH == "arm64" {
				return true, ""
			}
		}
		return false, "unsupported arch"
	case "syz_init_net_socket":
		// Unfortunately this only works with sandbox none at the moment.
		// The problem is that setns of a network namespace requires CAP_SYS_ADMIN
		// in the target namespace, and we've lost all privs in the init namespace
		// during creation of a user namespace.
		if ok, reason := onlySandboxNone(sandbox); !ok {
			return false, reason
		}
		return isSupportedSocket(c)
	case "syz_genetlink_get_family_id":
		fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
		if fd == -1 {
			return false, fmt.Sprintf("socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) failed: %v", err)
		}
		syscall.Close(fd)
		return true, ""
	case "syz_mount_image":
		return onlySandboxNone(sandbox)
	case "syz_read_part_table":
		return onlySandboxNone(sandbox)
	}
	panic("unknown syzkall: " + c.Name)
}

func onlySandboxNone(sandbox string) (bool, string) {
	if syscall.Getuid() != 0 || sandbox != "none" {
		return false, "only supported under root with sandbox=none"
	}
	return true, ""
}

func onlySandboxNoneOrNamespace(sandbox string) (bool, string) {
	if syscall.Getuid() != 0 || sandbox == "setuid" {
		return false, "only supported under root with sandbox=none/namespace"
	}
	return true, ""
}

func isSupportedSocket(c *prog.Syscall) (bool, string) {
	af, ok := c.Args[0].(*prog.ConstType)
	if !ok {
		panic("socket family is not const")
	}
	fd, err := syscall.Socket(int(af.Val), 0, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	if err == syscall.ENOSYS {
		return false, "socket syscall returns ENOSYS"
	}
	if err == syscall.EAFNOSUPPORT {
		return false, "socket family is not supported (EAFNOSUPPORT)"
	}
	return true, ""
}

func isSupportedOpenAt(c *prog.Syscall) (bool, string) {
	fname, ok := extractStringConst(c.Args[1])
	if !ok || len(fname) == 0 || fname[0] != '/' {
		return true, ""
	}
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	if err != nil {
		return false, fmt.Sprintf("open(%v) failed: %v", fname, err)
	}
	return true, ""
}

func extractStringConst(typ prog.Type) (string, bool) {
	ptr, ok := typ.(*prog.PtrType)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	str, ok := ptr.Type.(*prog.BufferType)
	if !ok || str.Kind != prog.BufferString || len(str.Values) != 1 {
		return "", false
	}
	v := str.Values[0]
	v = v[:len(v)-1] // string terminating \x00
	return v, true
}

func EnableFaultInjection() error {
	if err := osutil.WriteFile("/sys/kernel/debug/failslab/ignore-gfp-wait", []byte("N")); err != nil {
		return fmt.Errorf("failed to write /failslab/ignore-gfp-wait: %v", err)
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_futex/ignore-private", []byte("N")); err != nil {
		return fmt.Errorf("failed to write /fail_futex/ignore-private: %v", err)
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_page_alloc/ignore-gfp-highmem", []byte("N")); err != nil {
		return fmt.Errorf("failed to write /fail_page_alloc/ignore-gfp-highmem: %v", err)
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_page_alloc/ignore-gfp-wait", []byte("N")); err != nil {
		return fmt.Errorf("failed to write /fail_page_alloc/ignore-gfp-wait: %v", err)
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_page_alloc/min-order", []byte("0")); err != nil {
		return fmt.Errorf("failed to write /fail_page_alloc/min-order: %v", err)
	}
	return nil
}
