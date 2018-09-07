// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/linux"
)

func isSupported(c *prog.Syscall, sandbox string) (bool, string) {
	if strings.HasPrefix(c.CallName, "syz_") {
		return isSupportedSyzkall(sandbox, c)
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
		kallsyms, _ = ioutil.ReadFile("/proc/kallsyms")
	})
	if !testFallback && len(kallsyms) != 0 {
		return isSupportedKallsyms(c)
	}
	return isSupportedTrial(c)
}

func isSupportedKallsyms(c *prog.Syscall) (bool, string) {
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
	kallsyms     []byte
	kallsymsOnce sync.Once
	kallsymsMap  = map[string]string{
		"umount":  "oldumount",
		"umount2": "umount",
	}
	trialMu         sync.Mutex
	trialSupported  = make(map[uint64]bool)
	filesystems     []byte
	filesystemsOnce sync.Once
)

// The function is lengthy as it handles all pseudo-syscalls,
// but it does not seem to cause comprehension problems as there is no shared state.
// Splitting this per-syscall will only increase code size.
// nolint: gocyclo
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
	case "syz_open_procfs":
		return true, ""
	case "syz_open_pts":
		return true, ""
	case "syz_emit_ethernet", "syz_extract_tcp_res":
		reason := checkNetworkInjection()
		return reason == "", reason
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
		if ok, reason := onlySandboxNone(sandbox); !ok {
			return ok, reason
		}
		fstype, ok := extractStringConst(c.Args[0])
		if !ok {
			panic("syz_mount_image arg is not string")
		}
		return isSupportedFilesystem(fstype)
	case "syz_read_part_table":
		return onlySandboxNone(sandbox)
	case "syz_execute_func":
		return true, ""
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
	proto, ok := c.Args[2].(*prog.ConstType)
	if !ok {
		return true, ""
	}
	var typ uint64
	if arg, ok := c.Args[1].(*prog.ConstType); ok {
		typ = arg.Val
	} else if arg, ok := c.Args[1].(*prog.FlagsType); ok {
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

func isSupportedMount(c *prog.Syscall, sandbox string) (bool, string) {
	fstype, ok := extractStringConst(c.Args[2])
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
	str, ok := ptr.Type.(*prog.BufferType)
	if !ok || str.Kind != prog.BufferString || len(str.Values) == 0 {
		return "", false
	}
	v := str.Values[0]
	for len(v) != 0 && v[len(v)-1] == 0 {
		v = v[:len(v)-1] // string terminating \x00
	}
	return v, true
}

func init() {
	checkFeature[FeatureCoverage] = checkCoverage
	checkFeature[FeatureComparisons] = checkComparisons
	checkFeature[FeatureSandboxSetuid] = unconditionallyEnabled
	checkFeature[FeatureSandboxNamespace] = checkSandboxNamespace
	checkFeature[FeatureSandboxAndroidUntrustedApp] = checkSandboxAndroidUntrustedApp
	checkFeature[FeatureFaultInjection] = checkFaultInjection
	setupFeature[FeatureFaultInjection] = setupFaultInjection
	checkFeature[FeatureLeakChecking] = checkLeakChecking
	setupFeature[FeatureLeakChecking] = setupLeakChecking
	callbFeature[FeatureLeakChecking] = callbackLeakChecking
	checkFeature[FeatureNetworkInjection] = checkNetworkInjection
	checkFeature[FeatureNetworkDevices] = checkNetworkDevices
}

func checkCoverage() string {
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	if !osutil.IsExist("/sys/kernel/debug/kcov") {
		return "CONFIG_KCOV is not enabled"
	}
	if err := osutil.IsAccessible("/sys/kernel/debug/kcov"); err != nil {
		return err.Error()
	}
	return ""
}

func checkComparisons() (reason string) {
	if reason = checkDebugFS(); reason != "" {
		return reason
	}
	// TODO(dvyukov): this should run under target arch.
	// E.g. KCOV ioctls were initially not supported on 386 (missing compat_ioctl),
	// and a 386 executor won't be able to use them, but an amd64 fuzzer will be.
	fd, err := syscall.Open("/sys/kernel/debug/kcov", syscall.O_RDWR, 0)
	if err != nil {
		return "CONFIG_KCOV is not enabled"
	}
	defer syscall.Close(fd)
	// Trigger host target lazy initialization, it will fill linux.KCOV_INIT_TRACE.
	// It's all wrong and needs to be refactored.
	if _, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH); err != nil {
		return fmt.Sprintf("failed to get target: %v", err)
	}
	coverSize := uintptr(64 << 10)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_INIT_TRACE, coverSize)
	if errno != 0 {
		return fmt.Sprintf("ioctl(KCOV_INIT_TRACE) failed: %v", errno)
	}
	mem, err := syscall.Mmap(fd, 0, int(coverSize*unsafe.Sizeof(uintptr(0))),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Sprintf("KCOV mmap failed: %v", err)
	}
	defer func() {
		if err := syscall.Munmap(mem); err != nil {
			reason = fmt.Sprintf("munmap failed: %v", err)
		}
	}()
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), linux.KCOV_ENABLE, linux.KCOV_TRACE_CMP)
	if errno != 0 {
		if errno == 524 { // ENOTSUPP
			return "CONFIG_KCOV_ENABLE_COMPARISONS is not enabled"
		}
		return fmt.Sprintf("ioctl(KCOV_TRACE_CMP) failed: %v", errno)
	}
	defer func() {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_DISABLE, 0)
		if errno != 0 {
			reason = fmt.Sprintf("ioctl(KCOV_DISABLE) failed: %v", errno)
		}
	}()
	return ""
}

func checkFaultInjection() string {
	if err := osutil.IsAccessible("/proc/self/make-it-fail"); err != nil {
		return "CONFIG_FAULT_INJECTION is not enabled"
	}
	if err := osutil.IsAccessible("/proc/thread-self/fail-nth"); err != nil {
		return "kernel does not have systematic fault injection support"
	}
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	if err := osutil.IsAccessible("/sys/kernel/debug/failslab/ignore-gfp-wait"); err != nil {
		return "CONFIG_FAULT_INJECTION_DEBUG_FS is not enabled"
	}
	return ""
}

func setupFaultInjection() error {
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

func checkLeakChecking() string {
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	if err := osutil.IsAccessible("/sys/kernel/debug/kmemleak"); err != nil {
		return "CONFIG_DEBUG_KMEMLEAK is not enabled"
	}
	return ""
}

func setupLeakChecking() error {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open /sys/kernel/debug/kmemleak: %v", err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("scan=off")); err != nil {
		// kmemleak returns EBUSY when kmemleak is already turned off.
		if err != syscall.EBUSY {
			return fmt.Errorf("write(kmemleak, scan=off) failed: %v", err)
		}
	}
	// Flush boot leaks.
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		return fmt.Errorf("write(kmemleak, scan) failed: %v", err)
	}
	time.Sleep(5 * time.Second) // account for MSECS_MIN_AGE
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		return fmt.Errorf("write(kmemleak, scan) failed: %v", err)
	}
	if _, err := syscall.Write(fd, []byte("clear")); err != nil {
		return fmt.Errorf("write(kmemleak, clear) failed: %v", err)
	}
	return nil
}

func callbackLeakChecking() {
	start := time.Now()
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	// KMEMLEAK has false positives. To mitigate most of them, it checksums
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
	buf := make([]byte, 128<<10)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		panic(err)
	}
	if n != 0 {
		time.Sleep(time.Second)
		if _, err := syscall.Write(fd, []byte("scan")); err != nil {
			panic(err)
		}
		n, err := syscall.Read(fd, buf)
		if err != nil {
			panic(err)
		}
		nleaks := 0
		for buf = buf[:n]; len(buf) != 0; {
			end := bytes.Index(buf[1:], []byte("unreferenced object"))
			if end != -1 {
				end++
			} else {
				end = len(buf)
			}
			report := buf[:end]
			buf = buf[end:]
			if kmemleakIgnore(report) {
				continue
			}
			// BUG in output should be recognized by manager.
			fmt.Printf("BUG: memory leak\n%s\n", report)
			nleaks++
		}
		if nleaks != 0 {
			os.Exit(1)
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

func checkSandboxNamespace() string {
	if err := osutil.IsAccessible("/proc/self/ns/user"); err != nil {
		return err.Error()
	}
	return ""
}

func checkSandboxAndroidUntrustedApp() string {
	if err := osutil.IsAccessible("/sys/fs/selinux/policy"); err != nil {
		return err.Error()
	}
	return ""
}

func checkNetworkInjection() string {
	if err := osutil.IsAccessible("/dev/net/tun"); err != nil {
		return err.Error()
	}
	return checkNetworkDevices()
}

func checkNetworkDevices() string {
	if _, err := exec.LookPath("ip"); err != nil {
		return "ip command is not found"
	}
	return ""
}

func checkDebugFS() string {
	if err := osutil.IsAccessible("/sys/kernel/debug"); err != nil {
		return "debugfs is not enabled or not mounted"
	}
	return ""
}
