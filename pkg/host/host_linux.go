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
	"syscall"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

// DetectSupportedSyscalls returns list on supported syscalls on host.
func DetectSupportedSyscalls(target *prog.Target, sandbox string) (map[*prog.Syscall]bool, error) {
	// There are 3 possible strategies:
	// 1. Executes all syscalls with presumably invalid arguments and check for ENOprog.
	//    But not all syscalls are safe to execute. For example, pause will hang,
	//    while setpgrp will push the process into own process group.
	// 2. Check presence of /sys/kernel/debug/tracing/events/syscalls/sys_enter_* files.
	//    This requires root and CONFIG_FTRACE_SYSCALLS. Also it lies for some syscalls.
	//    For example, on x86_64 it says that sendfile is not present (only sendfile64).
	// 3. Check sys_syscallname in /proc/kallsyms.
	//    Requires CONFIG_KALLSYMS. Seems to be the most reliable. That's what we use here.

	kallsyms, _ := ioutil.ReadFile("/proc/kallsyms")
	supported := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		if isSupported(sandbox, kallsyms, c) {
			supported[c] = true
		}
	}
	return supported, nil
}

func isSupported(sandbox string, kallsyms []byte, c *prog.Syscall) bool {
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
		return true
	}
	name := c.CallName
	if newname := kallsymsMap[name]; newname != "" {
		name = newname
	}
	return bytes.Contains(kallsyms, []byte(" T sys_"+name+"\n"))
}

// Some syscall names diverge in __NR_* consts and kallsyms.
// umount2 is renamed to umount in arch/x86/entry/syscalls/syscall_64.tbl.
// Where umount is renamed to oldumount is unclear.
var kallsymsMap = map[string]string{
	"umount":  "oldumount",
	"umount2": "umount",
}

func isSupportedSyzkall(sandbox string, c *prog.Syscall) bool {
	switch c.CallName {
	case "syz_open_dev":
		if _, ok := c.Args[0].(*prog.ConstType); ok {
			// This is for syz_open_dev$char/block.
			// They are currently commented out, but in case one enables them.
			return true
		}
		fname, ok := extractStringConst(c.Args[0])
		if !ok {
			panic("first open arg is not a pointer to string const")
		}
		if syscall.Getuid() != 0 || sandbox == "setuid" {
			return false
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
		return check(fname)
	case "syz_open_procfs":
		return true
	case "syz_open_pts":
		return true
	case "syz_fuse_mount":
		if syscall.Getuid() != 0 || sandbox == "setuid" {
			return false
		}
		return osutil.IsExist("/dev/fuse")
	case "syz_fuseblk_mount":
		if syscall.Getuid() != 0 || sandbox == "setuid" {
			return false
		}
		return osutil.IsExist("/dev/fuse")
	case "syz_emit_ethernet", "syz_extract_tcp_res":
		fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
		if err == nil {
			syscall.Close(fd)
		}
		return err == nil
	case "syz_kvm_setup_cpu":
		switch c.Name {
		case "syz_kvm_setup_cpu$x86":
			return runtime.GOARCH == "amd64" || runtime.GOARCH == "386"
		case "syz_kvm_setup_cpu$arm64":
			return runtime.GOARCH == "arm64"
		}
	case "syz_init_net_socket":
		// Unfortunately this only works with sandbox none at the moment.
		// The problem is that setns of a network namespace requires CAP_SYS_ADMIN
		// in the target namespace, and we've lost all privs in the init namespace
		// during creation of a user namespace.
		if syscall.Getuid() != 0 || sandbox != "none" {
			return false
		}
		return isSupportedSocket(c)
	case "syz_genetlink_get_family_id":
		fd, _ := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
		if fd == -1 {
			return false
		}
		syscall.Close(fd)
		return true
	case "syz_mount_image":
		return sandbox != "setuid"
	case "syz_read_part_table":
		return sandbox == "none" && syscall.Getuid() == 0
	}
	panic("unknown syzkall: " + c.Name)
}

func isSupportedSocket(c *prog.Syscall) bool {
	af, ok := c.Args[0].(*prog.ConstType)
	if !ok {
		panic("socket family is not const")
	}
	fd, err := syscall.Socket(int(af.Val), 0, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	return err != syscall.ENOSYS && err != syscall.EAFNOSUPPORT
}

func isSupportedOpenAt(c *prog.Syscall) bool {
	fname, ok := extractStringConst(c.Args[1])
	if !ok || len(fname) == 0 || fname[0] != '/' {
		return true
	}
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if fd != -1 {
		syscall.Close(fd)
	}
	return err == nil
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
		return fmt.Errorf("failed to write /sys/kernel/debug/failslab/ignore-gfp-wait: %v", err)
	}
	if err := osutil.WriteFile("/sys/kernel/debug/fail_futex/ignore-private", []byte("N")); err != nil {
		return fmt.Errorf("failed to write /sys/kernel/debug/fail_futex/ignore-private: %v", err)
	}
	return nil
}
