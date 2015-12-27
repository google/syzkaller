// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"io/ioutil"
	"os"
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

	kallsyms, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	supported := make(map[*sys.Call]bool)
	tested := make(map[string]bool)
	for _, c := range sys.Calls {
		if _, ok := tested[c.CallName]; !ok {
			tested[c.CallName] = isSupported(kallsyms, c)
		}
		if tested[c.CallName] {
			supported[c] = true
		}
	}
	return supported, nil
}

func isSupported(kallsyms []byte, c *sys.Call) bool {
	// TODO: detect unsupported socket families.
	// TOOD: detect syscalls that open /dev/ files (e.g. open$ptmx).
	if c.NR == -1 {
		return false // don't even have a syscall number
	}
	if !strings.HasPrefix(c.CallName, "syz_") {
		return bytes.Index(kallsyms, []byte(" T sys_"+c.CallName+"\n")) != -1
	}
	switch c.CallName {
	case "syz_openpts":
		return true
	case "syz_dri_open":
		_, err := os.Stat("/dev/dri/card0")
		return err == nil
	case "syz_fuse_mount":
		_, err := os.Stat("/dev/fuse")
		return err == nil
	case "syz_fuseblk_mount":
		_, err := os.Stat("/dev/fuse")
		return err == nil && syscall.Getuid() == 0
	default:
		panic("unknown syzkall")
	}
}
