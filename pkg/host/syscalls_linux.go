// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func isSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	log.Logf(2, "checking support for %v", c.Name)
	if strings.HasPrefix(c.CallName, "syz_") {
		return isSupportedSyzkall(c, target, sandbox)
	}
	if reason := isSupportedLSM(c); reason != "" {
		return false, reason
	}
	if strings.HasPrefix(c.Name, "socket$") ||
		strings.HasPrefix(c.Name, "socketpair$") {
		return isSupportedSocket(c)
	}
	if strings.HasPrefix(c.Name, "openat$") {
		return isSupportedOpenAt(c)
	}
	if strings.HasPrefix(c.Name, "mount$") {
		return isSupportedMount(c, sandbox)
	}
	if c.Name == "ioctl$EXT4_IOC_SHUTDOWN" && sandbox == "none" {
		// Don't shutdown root filesystem.
		return false, "unsafe with sandbox=none"
	}
	return isSupportedSyscall(c, target)
}

func isSupportedSyscall(c *prog.Syscall, target *prog.Target) (bool, string) {
	// There are 3 possible strategies for detecting supported syscalls:
	// 1. Executes all syscalls with presumably invalid arguments and check for ENOprog.
	//    But not all syscalls are safe to execute. For example, pause will hang,
	//    while setpgrp will push the process into own process group.
	// 2. Check presence of /sys/kernel/debug/tracing/events/syscalls/sys_enter_* files.
	//    This requires root and CONFIG_FTRACE_SYSCALLS. Also it lies for some syscalls.
	//    For example, on x86_64 it says that sendfile is not present (only sendfile64).
	// 3. Check sys_syscallname in /proc/kallsyms.
	//    Requires CONFIG_KALLSYMS.
	// Kallsyms seems to be the most reliable and fast. That's what we use first.
	// If kallsyms is not present, we fallback to execution of syscalls.
	kallsymsOnce.Do(func() {
		kallsyms, _ := ioutil.ReadFile("/proc/kallsyms")
		if len(kallsyms) == 0 {
			return
		}
		kallsymsSyscallSet = parseKallsyms(kallsyms, target.Arch)
	})
	if !testFallback && len(kallsymsSyscallSet) != 0 {
		r, v := isSupportedKallsyms(c)
		return r, v
	}
	return isSupportedTrial(c)
}

func parseKallsyms(kallsyms []byte, arch string) map[string]bool {
	set := make(map[string]bool)
	var re *regexp.Regexp
	switch arch {
	case "386", "amd64":
		re = regexp.MustCompile(` T (__ia32_|__x64_)?sys_([^\n]+)\n`)
	case "arm", "arm64":
		re = regexp.MustCompile(` T (__arm64_)?sys_([^\n]+)\n`)
	case "ppc64le":
		re = regexp.MustCompile(` T ()?sys_([^\n]+)\n`)
	case "mips64le":
		re = regexp.MustCompile(` T sys_(mips_)?([^\n]+)\n`)
	case "s390x":
		re = regexp.MustCompile(` T (__s390_|__s390x_)?sys_([^\n]+)\n`)
	case "riscv64":
		re = regexp.MustCompile(` T sys_(riscv_)?([^\n]+)\n`)
	default:
		panic("unsupported arch for kallsyms parsing")
	}
	matches := re.FindAllSubmatch(kallsyms, -1)
	for _, m := range matches {
		name := string(m[2])
		log.Logf(2, "found in kallsyms: %v", name)
		set[name] = true
	}
	return set
}

func isSupportedKallsyms(c *prog.Syscall) (bool, string) {
	name := c.CallName
	if newname := kallsymsRenameMap[name]; newname != "" {
		name = newname
	}
	if !kallsymsSyscallSet[name] {
		return false, fmt.Sprintf("sys_%v is not present in /proc/kallsyms", name)
	}
	return true, ""
}

func isSupportedTrial(c *prog.Syscall) (bool, string) {
	switch c.CallName {
	// These known to cause hangs.
	case "exit", "pause":
		return true, ""
	}
	trialMu.Lock()
	defer trialMu.Unlock()
	if res, ok := trialSupported[c.NR]; ok {
		return res, "ENOSYS"
	}
	cmd := osutil.Command(os.Args[0])
	cmd.Env = []string{fmt.Sprintf("SYZ_TRIAL_TEST=%v", c.NR)}
	_, err := osutil.Run(10*time.Second, cmd)
	res := err != nil
	trialSupported[c.NR] = res
	return res, "ENOSYS"
}

func init() {
	str := os.Getenv("SYZ_TRIAL_TEST")
	if str == "" {
		return
	}
	nr, err := strconv.Atoi(str)
	if err != nil {
		panic(err)
	}
	arg := ^uintptr(0) - 1e4 // something as invalid as possible
	_, _, err = syscall.Syscall6(uintptr(nr), arg, arg, arg, arg, arg, arg)
	if err == syscall.ENOSYS {
		os.Exit(0)
	}
	os.Exit(1)
}

// Some syscall names diverge in __NR_* consts and kallsyms.
// umount2 is renamed to umount in arch/x86/entry/syscalls/syscall_64.tbl.
// Where umount is renamed to oldumount is unclear.
var (
	kallsymsOnce       sync.Once
	kallsymsSyscallSet map[string]bool
	kallsymsRenameMap  = map[string]string{
		"umount":  "oldumount",
		"umount2": "umount",
		"stat":    "newstat",
	}
	trialMu         sync.Mutex
	trialSupported  = make(map[uint64]bool)
	filesystems     []byte
	filesystemsOnce sync.Once
	lsmOnce         sync.Once
	lsmError        error
	lsmDisabled     map[string]bool
)

func isSyzUsbSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	reason := checkUSBEmulation()
	return reason == "", reason
}

func alwaysSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	return true, ""
}

func isNetInjectionSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	reason := checkNetInjection()
	return reason == "", reason
}

func isVhciInjectionSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	reason := checkVhciInjection()
	return reason == "", reason
}

func isSyzKvmSetupCPUSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
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
}

func isSyzOpenDevSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	return isSupportedSyzOpenDev(sandbox, c)
}

func isSyzInitNetSocketSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if ok, reason := onlySandboxNone(sandbox); !ok {
		return false, reason
	}
	return isSupportedSocket(c)
}

func isSyzGenetlinkGetFamilyIDSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
	if fd == -1 {
		return false, fmt.Sprintf("socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) failed: %v", err)
	}
	syscall.Close(fd)
	return true, ""
}
func isSyzMountImageSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if ok, reason := onlySandboxNone(sandbox); !ok {
		return ok, reason
	}
	fstype, ok := extractStringConst(c.Args[0].Type)
	if !ok {
		panic("syz_mount_image arg is not string")
	}
	return isSupportedFilesystem(fstype)
}

func isSyzReadPartTableSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	return onlySandboxNone(sandbox)
}

func isSyzIoUringSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	ioUringSyscallName := "io_uring_setup"
	ioUringSyscall := target.SyscallMap[ioUringSyscallName]
	if ioUringSyscall == nil {
		return false, fmt.Sprintf("sys_%v is not present in the target", ioUringSyscallName)
	}
	return isSupportedSyscall(ioUringSyscall, target)
}

func isBtfVmlinuxSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if err := osutil.IsAccessible("/sys/kernel/btf/vmlinux"); err != nil {
		return false, err.Error()
	}
	return onlySandboxNone(sandbox)
}

func isSyzFuseSupported(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if ok, reason := isSupportedFilesystem("fuse"); !ok {
		return ok, reason
	}
	if ok, reason := onlySandboxNoneOrNamespace(sandbox); !ok {
		return false, reason
	}
	return true, ""
}

var syzkallSupport = map[string]func(*prog.Syscall, *prog.Target, string) (bool, string){
	"syz_open_dev":                isSyzOpenDevSupported,
	"syz_open_procfs":             alwaysSupported,
	"syz_open_pts":                alwaysSupported,
	"syz_execute_func":            alwaysSupported,
	"syz_emit_ethernet":           isNetInjectionSupported,
	"syz_extract_tcp_res":         isNetInjectionSupported,
	"syz_usb_connect":             isSyzUsbSupported,
	"syz_usb_connect_ath9k":       isSyzUsbSupported,
	"syz_usb_disconnect":          isSyzUsbSupported,
	"syz_usb_control_io":          isSyzUsbSupported,
	"syz_usb_ep_write":            isSyzUsbSupported,
	"syz_usb_ep_read":             isSyzUsbSupported,
	"syz_kvm_setup_cpu":           isSyzKvmSetupCPUSupported,
	"syz_emit_vhci":               isVhciInjectionSupported,
	"syz_init_net_socket":         isSyzInitNetSocketSupported,
	"syz_genetlink_get_family_id": isSyzGenetlinkGetFamilyIDSupported,
	"syz_mount_image":             isSyzMountImageSupported,
	"syz_read_part_table":         isSyzReadPartTableSupported,
	"syz_io_uring_submit":         isSyzIoUringSupported,
	"syz_io_uring_complete":       isSyzIoUringSupported,
	"syz_io_uring_setup":          isSyzIoUringSupported,
	// syz_memcpy_off is only used for io_uring descriptions, thus, enable it
	// only if io_uring syscalls are enabled.
	"syz_memcpy_off":      isSyzIoUringSupported,
	"syz_btf_id_by_name":  isBtfVmlinuxSupported,
	"syz_fuse_handle_req": isSyzFuseSupported,
}

func isSupportedSyzkall(c *prog.Syscall, target *prog.Target, sandbox string) (bool, string) {
	if isSupported, ok := syzkallSupport[c.CallName]; ok {
		return isSupported(c, target, sandbox)
	}
	panic("unknown syzkall: " + c.Name)
}

func isSupportedSyzOpenDev(sandbox string, c *prog.Syscall) (bool, string) {
	if _, ok := c.Args[0].Type.(*prog.ConstType); ok {
		// This is for syz_open_dev$char/block.
		return true, ""
	}
	fname, ok := extractStringConst(c.Args[0].Type)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	if strings.Contains(fname, "/dev/raw/raw#") {
		// For syz_open_dev$char_raw, these files don't exist initially.
		return true, ""
	}
	if !strings.Contains(fname, "#") {
		panic(fmt.Sprintf("%v does not contain # in the file name (should be openat)", c.Name))
	}
	if checkUSBEmulation() == "" {
		// These entries might not be available at boot time,
		// but will be created by connected USB devices.
		USBDevicePrefixes := []string{
			"/dev/hidraw", "/dev/usb/hiddev", "/dev/input/",
		}
		for _, prefix := range USBDevicePrefixes {
			if strings.HasPrefix(fname, prefix) {
				return true, ""
			}
		}
	}
	var check func(dev string) bool
	check = func(dev string) bool {
		if !strings.Contains(dev, "#") {
			// Note: don't try to open them all, some can hang (e.g. /dev/snd/pcmC#D#p).
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
}

func isSupportedLSM(c *prog.Syscall) string {
	lsmOnce.Do(func() {
		data, err := ioutil.ReadFile("/sys/kernel/security/lsm")
		if err != nil {
			// securityfs may not be mounted, but it does not mean
			// that no LSMs are enabled.
			if !os.IsNotExist(err) {
				lsmError = err
			}
			return
		}
		lsmDisabled = make(map[string]bool)
		for _, lsm := range []string{"selinux", "apparmor", "smack"} {
			if !strings.Contains(string(data), lsm) {
				lsmDisabled[lsm] = true
			}
		}
	})
	if lsmError != nil {
		return lsmError.Error()
	}
	for lsm := range lsmDisabled {
		if strings.Contains(strings.ToLower(c.Name), lsm) {
			return fmt.Sprintf("LSM %v is not enabled", lsm)
		}
	}
	return ""
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
	af, ok := c.Args[0].Type.(*prog.ConstType)
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
	proto, ok := c.Args[2].Type.(*prog.ConstType)
	if !ok {
		return true, ""
	}
	var typ uint64
	if arg, ok := c.Args[1].Type.(*prog.ConstType); ok {
		typ = arg.Val
	} else if arg, ok := c.Args[1].Type.(*prog.FlagsType); ok {
		typ = arg.Vals[0]
	} else {
		return true, ""
	}
	fd, err = syscall.Socket(int(af.Val), int(typ), int(proto.Val))
	if fd != -1 {
		syscall.Close(fd)
		return true, ""
	}
	return false, err.Error()
}

func isSupportedOpenAt(c *prog.Syscall) (bool, string) {
	var fd int
	var err error

	fname, ok := extractStringConst(c.Args[1].Type)
	if !ok || fname == "" || fname[0] != '/' {
		return true, ""
	}

	modes := []int{syscall.O_RDONLY, syscall.O_WRONLY, syscall.O_RDWR}

	// Attempt to extract flags from the syscall description.
	if mode, ok := c.Args[2].Type.(*prog.ConstType); ok {
		modes = []int{int(mode.Val)}
	}

	for _, mode := range modes {
		fd, err = syscall.Open(fname, mode, 0)
		if fd != -1 {
			syscall.Close(fd)
		}
		if err == nil {
			return true, ""
		}
	}

	return false, fmt.Sprintf("open(%v) failed: %v", fname, err)
}

func isSupportedMount(c *prog.Syscall, sandbox string) (bool, string) {
	fstype, ok := extractStringConst(c.Args[2].Type)
	if !ok {
		panic(fmt.Sprintf("%v: filesystem is not string const", c.Name))
	}
	if ok, reason := isSupportedFilesystem(fstype); !ok {
		return ok, reason
	}
	switch fstype {
	case "fuse", "fuseblk":
		if err := osutil.IsAccessible("/dev/fuse"); err != nil {
			return false, err.Error()
		}
		return onlySandboxNoneOrNamespace(sandbox)
	default:
		return onlySandboxNone(sandbox)
	}
}

func isSupportedFilesystem(fstype string) (bool, string) {
	filesystemsOnce.Do(func() {
		filesystems, _ = ioutil.ReadFile("/proc/filesystems")
	})
	if !bytes.Contains(filesystems, []byte("\t"+fstype+"\n")) {
		return false, fmt.Sprintf("/proc/filesystems does not contain %v", fstype)
	}
	return true, ""
}

func extractStringConst(typ prog.Type) (string, bool) {
	ptr, ok := typ.(*prog.PtrType)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	str, ok := ptr.Elem.(*prog.BufferType)
	if !ok || str.Kind != prog.BufferString || len(str.Values) == 0 {
		return "", false
	}
	v := str.Values[0]
	for v != "" && v[len(v)-1] == 0 {
		v = v[:len(v)-1] // string terminating \x00
	}
	return v, true
}
