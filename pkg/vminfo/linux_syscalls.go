// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func (linux) syscallCheck(ctx *checkContext, call *prog.Syscall) string {
	check := linuxSyscallChecks[call.CallName]
	if check == nil {
		check = func(ctx *checkContext, call *prog.Syscall) string {
			// Execute plain syscall (rather than a variation with $) to make test program
			// deduplication effective. However, if the plain syscall does not exist take
			// the first variant for this syscall, this still allows to dedup all variants.
			// This works b/c in syscall test we only check for ENOSYS result.
			name := call.CallName
			if ctx.target.SyscallMap[name] == nil {
				for _, call1 := range ctx.target.Syscalls {
					if name == call1.CallName {
						name = call1.Name
					}
				}
			}
			return ctx.supportedSyscalls([]string{name})
		}
	}
	if reason := check(ctx, call); reason != "" {
		return reason
	}
	return linuxSupportedLSM(ctx, call)
}

func linuxSupportedLSM(ctx *checkContext, call *prog.Syscall) string {
	for _, lsm := range []string{"selinux", "apparmor", "smack"} {
		if !strings.Contains(strings.ToLower(call.Name), lsm) {
			continue
		}
		data, err := ctx.readFile("/sys/kernel/security/lsm")
		if err != nil {
			// Securityfs may not be mounted, but it does not mean that no LSMs are enabled.
			if os.IsNotExist(err) {
				break
			}
			return err.Error()
		}
		if !bytes.Contains(data, []byte(lsm)) {
			return fmt.Sprintf("%v is not enabled", lsm)
		}
	}
	return ""
}

var linuxSyscallChecks = map[string]func(*checkContext, *prog.Syscall) string{
	"openat":                      supportedOpenat,
	"mount":                       linuxSupportedMount,
	"socket":                      linuxSupportedSocket,
	"socketpair":                  linuxSupportedSocket,
	"pkey_alloc":                  linuxPkeysSupported,
	"syz_open_dev":                linuxSyzOpenDevSupported,
	"syz_open_procfs":             linuxSyzOpenProcfsSupported,
	"syz_open_pts":                alwaysSupported,
	"syz_execute_func":            alwaysSupported,
	"syz_emit_ethernet":           linuxNetInjectionSupported,
	"syz_extract_tcp_res":         linuxNetInjectionSupported,
	"syz_usb_connect":             linuxCheckUSBEmulation,
	"syz_usb_connect_ath9k":       linuxCheckUSBEmulation,
	"syz_usb_disconnect":          linuxCheckUSBEmulation,
	"syz_usb_control_io":          linuxCheckUSBEmulation,
	"syz_usb_ep_write":            linuxCheckUSBEmulation,
	"syz_usb_ep_read":             linuxCheckUSBEmulation,
	"syz_kvm_setup_cpu":           linuxSyzKvmSetupCPUSupported,
	"syz_emit_vhci":               linuxVhciInjectionSupported,
	"syz_init_net_socket":         linuxSyzInitNetSocketSupported,
	"syz_genetlink_get_family_id": linuxSyzGenetlinkGetFamilyIDSupported,
	"syz_mount_image":             linuxSyzMountImageSupported,
	"syz_read_part_table":         linuxSyzReadPartTableSupported,
	"syz_io_uring_setup":          alwaysSupported,
	"syz_io_uring_submit":         alwaysSupported,
	"syz_io_uring_complete":       alwaysSupported,
	"syz_memcpy_off":              alwaysSupported,
	"syz_btf_id_by_name":          linuxBtfVmlinuxSupported,
	"syz_fuse_handle_req":         alwaysSupported,
	"syz_80211_inject_frame":      linuxWifiEmulationSupported,
	"syz_80211_join_ibss":         linuxWifiEmulationSupported,
	"syz_usbip_server_init":       linuxSyzUsbIPSupported,
	"syz_clone":                   alwaysSupported,
	"syz_clone3":                  alwaysSupported,
	"syz_pkey_set":                linuxPkeysSupported,
	"syz_socket_connect_nvme_tcp": linuxSyzSocketConnectNvmeTCPSupported,
	"syz_pidfd_open":              alwaysSupported,
}

func linuxSyzOpenDevSupported(ctx *checkContext, call *prog.Syscall) string {
	if _, ok := call.Args[0].Type.(*prog.ConstType); ok {
		// This is for syz_open_dev$char/block.
		return ""
	}
	fname, ok := extractStringConst(call.Args[0].Type)
	if !ok {
		panic("first open arg is not a pointer to string const")
	}
	hashCount := strings.Count(fname, "#")
	if hashCount == 0 {
		panic(fmt.Sprintf("%v does not contain # in the file name", call.Name))
	}
	if hashCount > 2 {
		// If this fails, the logic below needs an adjustment.
		panic(fmt.Sprintf("%v contains too many #", call.Name))
	}
	var ids []int
	if _, ok := call.Args[1].Type.(*prog.ProcType); ok {
		ids = []int{0}
	} else {
		for i := 0; i < 5; i++ {
			for j := 0; j < 5; j++ {
				if j == 0 || hashCount > 1 {
					ids = append(ids, i+j*10)
				}
			}
		}
	}
	modes := ctx.allOpenModes()
	var calls []string
	for _, id := range ids {
		for _, mode := range modes {
			call := fmt.Sprintf("%s(&AUTO='%v', 0x%x, 0x%x)", call.Name, fname, id, mode)
			calls = append(calls, call)
		}
	}
	reason := ctx.anyCallSucceeds(calls, fmt.Sprintf("failed to open %v", fname))
	if reason != "" {
		// These entries might not be available at boot time,
		// but will be created by connected USB devices.
		for _, prefix := range []string{"/dev/hidraw", "/dev/usb/hiddev", "/dev/input/"} {
			if strings.HasPrefix(fname, prefix) {
				// Note: ideally we use linuxSyzOpenDevSupported here,
				// since we already issued test syscalls, we can't.
				if _, err := ctx.readFile("/dev/raw-gadget"); !os.IsNotExist(err) {
					reason = ""
				}
			}
		}
	}
	return reason
}

func linuxNetInjectionSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.rootCanOpen("/dev/net/tun")
}

func linuxSyzOpenProcfsSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.canOpen("/proc/cmdline")
}

func linuxCheckUSBEmulation(ctx *checkContext, call *prog.Syscall) string {
	return ctx.rootCanOpen("/dev/raw-gadget")
}

func linuxSyzKvmSetupCPUSupported(ctx *checkContext, call *prog.Syscall) string {
	switch call.Name {
	case "syz_kvm_setup_cpu$x86":
		if ctx.target.Arch == targets.AMD64 || ctx.target.Arch == targets.I386 {
			return ""
		}
	case "syz_kvm_setup_cpu$arm64":
		if ctx.target.Arch == targets.ARM64 {
			return ""
		}
	case "syz_kvm_setup_cpu$ppc64":
		if ctx.target.Arch == targets.PPC64LE {
			return ""
		}
	}
	return "unsupported arch"
}

func linuxSupportedMount(ctx *checkContext, call *prog.Syscall) string {
	return linuxSupportedFilesystem(ctx, call, 2)
}

func linuxSyzMountImageSupported(ctx *checkContext, call *prog.Syscall) string {
	return linuxSupportedFilesystem(ctx, call, 0)
}

func linuxSupportedFilesystem(ctx *checkContext, call *prog.Syscall, fsarg int) string {
	fstype, ok := extractStringConst(call.Args[fsarg].Type)
	if !ok {
		panic(fmt.Sprintf("%v: filesystem is not string const", call.Name))
	}
	switch fstype {
	case "fuse", "fuseblk":
		if reason := ctx.canOpen("/dev/fuse"); reason != "" {
			return reason
		}
		if reason := ctx.onlySandboxNoneOrNamespace(); reason != "" {
			return reason
		}
	default:
		if reason := ctx.onlySandboxNone(); reason != "" {
			return reason
		}
	}
	filesystems, err := ctx.readFile("/proc/filesystems")
	if err != nil {
		return err.Error()
	}
	if !bytes.Contains(filesystems, []byte("\t"+fstype+"\n")) {
		return fmt.Sprintf("/proc/filesystems does not contain %v", fstype)
	}
	return ""
}

func linuxSyzReadPartTableSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.onlySandboxNone()
}

func linuxSupportedSocket(ctx *checkContext, call *prog.Syscall) string {
	if call.Name == "socket" || call.Name == "socketpair" {
		return "" // generic versions are always supported
	}
	af := uint64(0)
	if arg, ok := call.Args[0].Type.(*prog.ConstType); ok {
		af = arg.Val
	} else {
		panic(fmt.Sprintf("socket family is not const in %v", call.Name))
	}
	typ, hasType := uint64(0), false
	if arg, ok := call.Args[1].Type.(*prog.ConstType); ok {
		typ, hasType = arg.Val, true
	} else if arg, ok := call.Args[1].Type.(*prog.FlagsType); ok {
		typ, hasType = arg.Vals[0], true
	}
	proto, hasProto := uint64(0), false
	if arg, ok := call.Args[2].Type.(*prog.ConstType); ok {
		proto, hasProto = arg.Val, true
	}
	syscallName := call.Name
	if call.CallName == "socketpair" {
		syscallName = "socket"
	}
	callStr := fmt.Sprintf("%s(0x%x, 0x%x, 0x%x)", syscallName, af, typ, proto)
	errno := ctx.execCall(callStr)
	if errno == syscall.ENOSYS || errno == syscall.EAFNOSUPPORT || hasProto && hasType && errno != 0 {
		return fmt.Sprintf("%v failed: %v", callStr, errno)
	}
	return ""
}

func linuxSyzGenetlinkGetFamilyIDSupported(ctx *checkContext, call *prog.Syscall) string {
	// TODO: try to obtain actual family ID here. It will disable whole sets of sendmsg syscalls.
	return ctx.callSucceeds(fmt.Sprintf("socket(0x%x, 0x%x, 0x%x)",
		ctx.val("AF_NETLINK"), ctx.val("SOCK_RAW"), ctx.val("NETLINK_GENERIC")))
}

func linuxPkeysSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.callSucceeds("pkey_alloc(0x0, 0x0)")
}

func linuxSyzSocketConnectNvmeTCPSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.onlySandboxNone()
}

func linuxVhciInjectionSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.rootCanOpen("/dev/vhci")
}

func linuxSyzInitNetSocketSupported(ctx *checkContext, call *prog.Syscall) string {
	if reason := ctx.onlySandboxNone(); reason != "" {
		return reason
	}
	return linuxSupportedSocket(ctx, call)
}

func linuxBtfVmlinuxSupported(ctx *checkContext, call *prog.Syscall) string {
	if reason := ctx.onlySandboxNone(); reason != "" {
		return reason
	}
	return ctx.canOpen("/sys/kernel/btf/vmlinux")
}

func linuxSyzUsbIPSupported(ctx *checkContext, call *prog.Syscall) string {
	return ctx.canWrite("/sys/devices/platform/vhci_hcd.0/attach")
}

func linuxWifiEmulationSupported(ctx *checkContext, call *prog.Syscall) string {
	if reason := ctx.rootCanOpen("/sys/class/mac80211_hwsim/"); reason != "" {
		return reason
	}
	// We use HWSIM_ATTR_PERM_ADDR which was added in 4.17.
	return linuxRequireKernel(ctx, 4, 17)
}

func linuxRequireKernel(ctx *checkContext, major, minor int) string {
	data, err := ctx.readFile("/proc/version")
	if err != nil {
		return err.Error()
	}
	if ok, bad := matchKernelVersion(string(data), major, minor); bad {
		return fmt.Sprintf("failed to parse kernel version: %s", data)
	} else if !ok {
		return fmt.Sprintf("kernel %v.%v required, have %s", major, minor, data)
	}
	return ""
}

var kernelVersionRe = regexp.MustCompile(` ([0-9]+)\.([0-9]+)\.`)

func matchKernelVersion(ver string, x, y int) (bool, bool) {
	match := kernelVersionRe.FindStringSubmatch(ver)
	if match == nil {
		return false, true
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return false, true
	}
	if major <= 0 || major > 999 {
		return false, true
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return false, true
	}
	if minor <= 0 || minor > 999 {
		return false, true
	}
	return major*1000+minor >= x*1000+y, false
}
