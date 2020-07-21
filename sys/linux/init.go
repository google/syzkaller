// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"runtime"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix:                        targets.MakeUnixNeutralizer(target),
		clockGettimeSyscall:         target.SyscallMap["clock_gettime"],
		MREMAP_MAYMOVE:              target.GetConst("MREMAP_MAYMOVE"),
		MREMAP_FIXED:                target.GetConst("MREMAP_FIXED"),
		SYSLOG_ACTION_CONSOLE_OFF:   target.GetConst("SYSLOG_ACTION_CONSOLE_OFF"),
		SYSLOG_ACTION_CONSOLE_ON:    target.GetConst("SYSLOG_ACTION_CONSOLE_ON"),
		SYSLOG_ACTION_CONSOLE_LEVEL: target.GetConst("SYSLOG_ACTION_CONSOLE_LEVEL"),
		SYSLOG_ACTION_CLEAR:         target.GetConst("SYSLOG_ACTION_CLEAR"),
		SYSLOG_ACTION_SIZE_UNREAD:   target.GetConst("SYSLOG_ACTION_SIZE_UNREAD"),
		FIFREEZE:                    target.GetConst("FIFREEZE"),
		FITHAW:                      target.GetConst("FITHAW"),
		SNAPSHOT_FREEZE:             target.GetConst("SNAPSHOT_FREEZE"),
		SNAPSHOT_POWER_OFF:          target.GetConst("SNAPSHOT_POWER_OFF"),
		EXT4_IOC_SHUTDOWN:           target.GetConst("EXT4_IOC_SHUTDOWN"),
		EXT4_IOC_RESIZE_FS:          target.GetConst("EXT4_IOC_RESIZE_FS"),
		EXT4_IOC_MIGRATE:            target.GetConst("EXT4_IOC_MIGRATE"),
		FAN_OPEN_PERM:               target.GetConst("FAN_OPEN_PERM"),
		FAN_ACCESS_PERM:             target.GetConst("FAN_ACCESS_PERM"),
		FAN_OPEN_EXEC_PERM:          target.GetConst("FAN_OPEN_EXEC_PERM"),
		PTRACE_TRACEME:              target.GetConst("PTRACE_TRACEME"),
		CLOCK_REALTIME:              target.GetConst("CLOCK_REALTIME"),
		AF_NFC:                      target.GetConst("AF_NFC"),
		AF_LLC:                      target.GetConst("AF_LLC"),
		AF_BLUETOOTH:                target.GetConst("AF_BLUETOOTH"),
		AF_X25:                      target.GetConst("AF_X25"),
		AF_AX25:                     target.GetConst("AF_AX25"),
		AF_NETROM:                   target.GetConst("AF_NETROM"),
		AF_ROSE:                     target.GetConst("AF_ROSE"),
		USB_MAJOR:                   target.GetConst("USB_MAJOR"),
		TIOCSSERIAL:                 target.GetConst("TIOCSSERIAL"),
		TIOCGSERIAL:                 target.GetConst("TIOCGSERIAL"),
		// These are not present on all arches.
		ARCH_SET_FS: target.ConstMap["ARCH_SET_FS"],
		ARCH_SET_GS: target.ConstMap["ARCH_SET_GS"],
	}

	target.MakeDataMmap = targets.MakePosixMmap(target, true, true)
	target.Neutralize = arch.neutralize
	target.SpecialTypes = map[string]func(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
		prog.Arg, []*prog.Call){
		"timespec":                  arch.generateTimespec,
		"timeval":                   arch.generateTimespec,
		"sockaddr_alg":              arch.generateSockaddrAlg,
		"alg_name":                  arch.generateAlgName,
		"alg_aead_name":             arch.generateAlgAeadName,
		"alg_hash_name":             arch.generateAlgHashName,
		"alg_skcipher_name":         arch.generateAlgSkcipherhName,
		"ipt_replace":               arch.generateIptables,
		"ip6t_replace":              arch.generateIptables,
		"arpt_replace":              arch.generateArptables,
		"ebt_replace":               arch.generateEbtables,
		"usb_device_descriptor":     arch.generateUsbDeviceDescriptor,
		"usb_device_descriptor_hid": arch.generateUsbHidDeviceDescriptor,
	}

	target.AuxResources = map[string]bool{
		"uid":       true,
		"pid":       true,
		"gid":       true,
		"timespec":  true,
		"timeval":   true,
		"time_sec":  true,
		"time_usec": true,
		"time_nsec": true,
	}

	switch target.Arch {
	case "amd64":
		target.SpecialPointers = []uint64{
			0xffffffff81000000, // kernel text
		}
	case "386", "arm64", "arm", "ppc64le", "mips64le", "s390x", "riscv64":
	default:
		panic("unknown arch")
	}

	if target.Arch == runtime.GOARCH {
		KCOV_INIT_TRACE = uintptr(target.GetConst("KCOV_INIT_TRACE"))
		KCOV_ENABLE = uintptr(target.GetConst("KCOV_ENABLE"))
		KCOV_REMOTE_ENABLE = uintptr(target.GetConst("KCOV_REMOTE_ENABLE"))
		KCOV_DISABLE = uintptr(target.GetConst("KCOV_DISABLE"))
		KCOV_TRACE_PC = uintptr(target.GetConst("KCOV_TRACE_PC"))
		KCOV_TRACE_CMP = uintptr(target.GetConst("KCOV_TRACE_CMP"))
	}
}

var (
	// This should not be here, but for now we expose this for syz-fuzzer.
	KCOV_INIT_TRACE    uintptr
	KCOV_ENABLE        uintptr
	KCOV_REMOTE_ENABLE uintptr
	KCOV_DISABLE       uintptr
	KCOV_TRACE_PC      uintptr
	KCOV_TRACE_CMP     uintptr
)

type arch struct {
	unix *targets.UnixNeutralizer

	clockGettimeSyscall *prog.Syscall

	MREMAP_MAYMOVE              uint64
	MREMAP_FIXED                uint64
	SYSLOG_ACTION_CONSOLE_OFF   uint64
	SYSLOG_ACTION_CONSOLE_ON    uint64
	SYSLOG_ACTION_CONSOLE_LEVEL uint64
	SYSLOG_ACTION_CLEAR         uint64
	SYSLOG_ACTION_SIZE_UNREAD   uint64
	FIFREEZE                    uint64
	FITHAW                      uint64
	SNAPSHOT_FREEZE             uint64
	SNAPSHOT_POWER_OFF          uint64
	EXT4_IOC_SHUTDOWN           uint64
	EXT4_IOC_RESIZE_FS          uint64
	EXT4_IOC_MIGRATE            uint64
	FAN_OPEN_PERM               uint64
	FAN_ACCESS_PERM             uint64
	FAN_OPEN_EXEC_PERM          uint64
	PTRACE_TRACEME              uint64
	CLOCK_REALTIME              uint64
	ARCH_SET_FS                 uint64
	ARCH_SET_GS                 uint64
	AF_NFC                      uint64
	AF_LLC                      uint64
	AF_BLUETOOTH                uint64
	AF_X25                      uint64
	AF_AX25                     uint64
	AF_NETROM                   uint64
	AF_ROSE                     uint64
	USB_MAJOR                   uint64
	TIOCSSERIAL                 uint64
	TIOCGSERIAL                 uint64
}

func (arch *arch) neutralize(c *prog.Call) {
	arch.unix.Neutralize(c)
	switch c.Meta.CallName {
	case "mremap":
		// Add MREMAP_FIXED flag, otherwise it produces non-deterministic results.
		flags := c.Args[3].(*prog.ConstArg)
		if flags.Val&arch.MREMAP_MAYMOVE != 0 {
			flags.Val |= arch.MREMAP_FIXED
		}
	case "syslog":
		cmd := c.Args[0].(*prog.ConstArg)
		cmd.Val = uint64(uint32(cmd.Val))
		// These disable console output, but we need it.
		if cmd.Val == arch.SYSLOG_ACTION_CONSOLE_OFF ||
			cmd.Val == arch.SYSLOG_ACTION_CONSOLE_ON ||
			cmd.Val == arch.SYSLOG_ACTION_CONSOLE_LEVEL ||
			cmd.Val == arch.SYSLOG_ACTION_CLEAR {
			cmd.Val = arch.SYSLOG_ACTION_SIZE_UNREAD
		}
	case "ioctl":
		arch.neutralizeIoctl(c)
	case "fanotify_mark":
		// FAN_*_PERM require the program to reply to open requests.
		// If that does not happen, the program will hang in an unkillable state forever.
		// See the following bug for details:
		// https://groups.google.com/d/msg/syzkaller-bugs/pD-vbqJu6U0/kGH30p3lBgAJ
		mask := c.Args[2].(*prog.ConstArg)
		mask.Val &^= arch.FAN_OPEN_PERM | arch.FAN_ACCESS_PERM | arch.FAN_OPEN_EXEC_PERM
	case "ptrace":
		req := c.Args[0].(*prog.ConstArg)
		// PTRACE_TRACEME leads to unkillable processes, see:
		// https://groups.google.com/forum/#!topic/syzkaller/uGzwvhlCXAw
		if uint64(uint32(req.Val)) == arch.PTRACE_TRACEME {
			req.Val = ^uint64(0)
		}
	case "arch_prctl":
		// fs holds address of tls, if a program messes it at least signal
		// handling will break. This also allows a program to do writes
		// at arbitrary addresses, which usually leads to machine outbreak.
		cmd := c.Args[0].(*prog.ConstArg)
		if uint64(uint32(cmd.Val)) == arch.ARCH_SET_FS {
			cmd.Val = arch.ARCH_SET_GS
		}
	case "init_module":
		// Kernel tries to vmalloc whatever we pass as size and it's not accounted against memcg.
		// As the result it can lead to massive OOM kills of everything running on the machine.
		// Strictly saying, the same applies to finit_module with a sparse file too,
		// but there is no simple way to handle that.
		sz := c.Args[1].(*prog.ConstArg)
		sz.Val %= 1 << 20
	case "syz_init_net_socket":
		// Don't let it mess with arbitrary sockets in init namespace.
		family := c.Args[0].(*prog.ConstArg)
		switch uint64(uint32(family.Val)) {
		case arch.AF_NFC, arch.AF_LLC, arch.AF_BLUETOOTH,
			arch.AF_X25, arch.AF_AX25, arch.AF_NETROM, arch.AF_ROSE:
		default:
			family.Val = ^uint64(0)
		}
	case "syz_open_dev":
		enforceIntArg(c.Args[0])
		enforceIntArg(c.Args[1])
		enforceIntArg(c.Args[2])
	}

	switch c.Meta.Name {
	case "setsockopt$EBT_SO_SET_ENTRIES":
		arch.neutralizeEbtables(c)
	}
}

func enforceIntArg(a prog.Arg) {
	arg, ok := a.(*prog.ConstArg)
	if !ok {
		return
	}
	switch typ := arg.Type().(type) {
	case *prog.ConstType:
		arg.Val = typ.Val
	case *prog.IntType:
		if typ.Kind == prog.IntRange && (arg.Val < typ.RangeBegin || arg.Val > typ.RangeEnd) {
			arg.Val = typ.RangeBegin
		}
	}
}

func (arch *arch) neutralizeIoctl(c *prog.Call) {
	cmd := c.Args[1].(*prog.ConstArg)
	switch uint64(uint32(cmd.Val)) {
	case arch.FIFREEZE:
		// Freeze kills machine. Though, it is an interesting functions,
		// so we need to test it somehow.
		// TODO: not required if executor drops privileges.
		// Fortunately, the value does not conflict with any other ioctl commands for now.
		cmd.Val = arch.FITHAW
	case arch.SNAPSHOT_FREEZE:
		// SNAPSHOT_FREEZE freezes all processes and leaves the machine dead.
		cmd.Val = arch.FITHAW
	case arch.SNAPSHOT_POWER_OFF:
		// SNAPSHOT_POWER_OFF shuts down the machine.
		cmd.Val = arch.FITHAW
	case arch.EXT4_IOC_SHUTDOWN:
		// EXT4_IOC_SHUTDOWN on root fs effectively brings the machine down in weird ways.
		// Fortunately, the value does not conflict with any other ioctl commands for now.
		cmd.Val = arch.EXT4_IOC_MIGRATE
	case arch.EXT4_IOC_RESIZE_FS:
		// EXT4_IOC_RESIZE_FS on root fs can shrink it to 0 (or whatever is the minimum size)
		// and then creation of new temp dirs for tests will fail.
		// TODO: not necessary for sandbox=namespace as it tests in a tmpfs
		// and/or if we mount tmpfs for sandbox=none (#971).
		cmd.Val = arch.EXT4_IOC_MIGRATE
	case arch.TIOCSSERIAL:
		// TIOCSSERIAL can do nasty things under root, like causing writes to random memory
		// pretty much like /dev/mem, but this is also working as intended.
		// For details see:
		// https://groups.google.com/g/syzkaller-bugs/c/1rVENJf9P4U/m/QtGpapRxAgAJ
		// https://syzkaller.appspot.com/bug?extid=f4f1e871965064ae689e
		// TODO: TIOCSSERIAL does some other things that are not dangerous
		// and would be nice to test, if/when we can neutralize based on sandbox value
		// we could prohibit it only under sandbox=none.
		cmd.Val = arch.TIOCGSERIAL
	}
}

func (arch *arch) generateTimespec(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	// We need to generate timespec/timeval that are either
	// (1) definitely in the past, or
	// (2) definitely in unreachable fututre, or
	// (3) few ms ahead of now.
	// Note: timespec/timeval can be absolute or relative to now.
	// Note: executor has blocking syscall timeout of 45 ms,
	// so we generate both 10ms and 60ms.
	const (
		timeout1 = uint64(10)
		timeout2 = uint64(60)
	)
	usec := typ.Name() == "timeval"
	switch {
	case g.NOutOf(1, 4):
		// Now for relative, past for absolute.
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 0),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, 0),
		})
	case g.NOutOf(1, 3):
		// Few ms ahead for relative, past for absolute.
		nsec := timeout1 * 1e6
		if g.NOutOf(1, 2) {
			nsec = timeout2 * 1e6
		}
		if usec {
			nsec /= 1e3
		}
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 0),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, nsec),
		})
	case g.NOutOf(1, 2):
		// Unreachable fututre for both relative and absolute.
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 2e9),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, 0),
		})
	default:
		// Few ms ahead for absolute.
		meta := arch.clockGettimeSyscall
		ptrArgType := meta.Args[1].Type.(*prog.PtrType)
		argType := ptrArgType.Elem.(*prog.StructType)
		tp := prog.MakeGroupArg(argType, prog.DirOut, []prog.Arg{
			prog.MakeResultArg(argType.Fields[0].Type, prog.DirOut, nil, 0),
			prog.MakeResultArg(argType.Fields[1].Type, prog.DirOut, nil, 0),
		})
		var tpaddr prog.Arg
		tpaddr, calls = g.Alloc(ptrArgType, prog.DirIn, tp)
		gettime := &prog.Call{
			Meta: meta,
			Args: []prog.Arg{
				prog.MakeConstArg(meta.Args[0].Type, prog.DirIn, arch.CLOCK_REALTIME),
				tpaddr,
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		}
		calls = append(calls, gettime)
		sec := prog.MakeResultArg(typ.Fields[0].Type, dir, tp.Inner[0].(*prog.ResultArg), 0)
		nsec := prog.MakeResultArg(typ.Fields[1].Type, dir, tp.Inner[1].(*prog.ResultArg), 0)
		msec := timeout1
		if g.NOutOf(1, 2) {
			msec = timeout2
		}
		if usec {
			nsec.OpDiv = 1e3
			nsec.OpAdd = msec * 1e3
		} else {
			nsec.OpAdd = msec * 1e6
		}
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{sec, nsec})
	}
	return
}
