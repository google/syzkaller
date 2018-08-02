// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"runtime"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

/*
func init() {
	prog.RegisterTarget(gen.Target_amd64, initTarget)
	prog.RegisterTarget(gen.Target_386, initTarget)
	prog.RegisterTarget(gen.Target_arm64, initTarget)
	prog.RegisterTarget(gen.Target_arm, initTarget)
	prog.RegisterTarget(gen.Target_ppc64le, initTarget)
}
*/

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix:                      targets.MakeUnixSanitizer(target),
		clockGettimeSyscall:       target.SyscallMap["clock_gettime"],
		SYSLOG_ACTION_CONSOLE_OFF: target.ConstMap["SYSLOG_ACTION_CONSOLE_OFF"],
		SYSLOG_ACTION_CONSOLE_ON:  target.ConstMap["SYSLOG_ACTION_CONSOLE_ON"],
		SYSLOG_ACTION_SIZE_UNREAD: target.ConstMap["SYSLOG_ACTION_SIZE_UNREAD"],
		FIFREEZE:                  target.ConstMap["FIFREEZE"],
		FITHAW:                    target.ConstMap["FITHAW"],
		PTRACE_TRACEME:            target.ConstMap["PTRACE_TRACEME"],
		CLOCK_REALTIME:            target.ConstMap["CLOCK_REALTIME"],
		ARCH_SET_FS:               target.ConstMap["ARCH_SET_FS"],
		ARCH_SET_GS:               target.ConstMap["ARCH_SET_GS"],
		AF_NFC:                    target.ConstMap["AF_NFC"],
		AF_LLC:                    target.ConstMap["AF_LLC"],
		AF_BLUETOOTH:              target.ConstMap["AF_BLUETOOTH"],
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.sanitizeCall
	target.SpecialTypes = map[string]func(g *prog.Gen, typ prog.Type, old prog.Arg) (
		prog.Arg, []*prog.Call){
		"timespec":           arch.generateTimespec,
		"timeval":            arch.generateTimespec,
		"sockaddr_alg":       arch.generateSockaddrAlg,
		"alg_name":           arch.generateAlgName,
		"alg_aead_name":      arch.generateAlgAeadName,
		"alg_hash_name":      arch.generateAlgHashName,
		"alg_blkcipher_name": arch.generateAlgBlkcipherhName,
		"ipt_replace":        arch.generateIptables,
		"ip6t_replace":       arch.generateIptables,
		"arpt_replace":       arch.generateArptables,
		"ebt_replace":        arch.generateEbtables,
	}
	target.StringDictionary = stringDictionary

	if target.Arch == runtime.GOARCH {
		KCOV_INIT_TRACE = uintptr(target.ConstMap["KCOV_INIT_TRACE"])
		KCOV_ENABLE = uintptr(target.ConstMap["KCOV_ENABLE"])
		KCOV_DISABLE = uintptr(target.ConstMap["KCOV_DISABLE"])
		KCOV_TRACE_CMP = uintptr(target.ConstMap["KCOV_TRACE_CMP"])
	}
}

var (
	// This should not be here, but for now we expose this for syz-fuzzer.
	KCOV_INIT_TRACE uintptr
	KCOV_ENABLE     uintptr
	KCOV_DISABLE    uintptr
	KCOV_TRACE_CMP  uintptr

	// TODO(dvyukov): get rid of this, this must be in descriptions.
	stringDictionary = []string{"user", "keyring", "trusted", "system", "security", "selinux",
		"posix_acl_access", "mime_type", "md5sum", "nodev", "self",
		"bdev", "proc", "cgroup", "cpuset",
		"lo", "eth0", "eth1", "em0", "em1", "wlan0", "wlan1", "ppp0", "ppp1",
		"vboxnet0", "vboxnet1", "vmnet0", "vmnet1", "GPL"}
)

type arch struct {
	unix *targets.UnixSanitizer

	clockGettimeSyscall *prog.Syscall

	SYSLOG_ACTION_CONSOLE_OFF uint64
	SYSLOG_ACTION_CONSOLE_ON  uint64
	SYSLOG_ACTION_SIZE_UNREAD uint64
	FIFREEZE                  uint64
	FITHAW                    uint64
	PTRACE_TRACEME            uint64
	CLOCK_REALTIME            uint64
	ARCH_SET_FS               uint64
	ARCH_SET_GS               uint64
	AF_NFC                    uint64
	AF_LLC                    uint64
	AF_BLUETOOTH              uint64
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	arch.unix.SanitizeCall(c)
	switch c.Meta.CallName {
	case "syslog":
		cmd := c.Args[0].(*prog.ConstArg)
		cmd.Val = uint64(uint32(cmd.Val))
		// These disable console output, but we need it.
		if cmd.Val == arch.SYSLOG_ACTION_CONSOLE_OFF || cmd.Val == arch.SYSLOG_ACTION_CONSOLE_ON {
			cmd.Val = arch.SYSLOG_ACTION_SIZE_UNREAD
		}
	case "ioctl":
		cmd := c.Args[1].(*prog.ConstArg)
		// Freeze kills machine. Though, it is an interesting functions,
		// so we need to test it somehow.
		// TODO: not required if executor drops privileges.
		if uint64(uint32(cmd.Val)) == arch.FIFREEZE {
			cmd.Val = arch.FITHAW
		}
	case "ptrace":
		req := c.Args[0].(*prog.ConstArg)
		// PTRACE_TRACEME leads to unkillable processes, see:
		// https://groups.google.com/forum/#!topic/syzkaller/uGzwvhlCXAw
		if req.Val == arch.PTRACE_TRACEME {
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
	case "syz_init_net_socket":
		// Don't let it mess with arbitrary sockets in init namespace.
		family := c.Args[0].(*prog.ConstArg)
		switch uint64(uint32(family.Val)) {
		case arch.AF_NFC, arch.AF_LLC, arch.AF_BLUETOOTH:
		default:
			family.Val = ^uint64(0)
		}
	}

	switch c.Meta.Name {
	case "setsockopt$EBT_SO_SET_ENTRIES":
		arch.sanitizeEbtables(c)
	}
}

func (arch *arch) generateTimespec(g *prog.Gen, typ0 prog.Type, old prog.Arg) (arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	// We need to generate timespec/timeval that are either
	// (1) definitely in the past, or
	// (2) definitely in unreachable fututre, or
	// (3) few ms ahead of now.
	// Note: timespec/timeval can be absolute or relative to now.
	// Note: executor has blocking syscall timeout of 20ms,
	// so we generate both 10ms and 30ms.
	usec := typ.Name() == "timeval"
	switch {
	case g.NOutOf(1, 4):
		// Now for relative, past for absolute.
		arg = prog.MakeGroupArg(typ, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0], nil, 0),
			prog.MakeResultArg(typ.Fields[1], nil, 0),
		})
	case g.NOutOf(1, 3):
		// Few ms ahead for relative, past for absolute
		nsec := uint64(10 * 1e6)
		if g.NOutOf(1, 2) {
			nsec = 30 * 1e6
		}
		if usec {
			nsec /= 1e3
		}
		arg = prog.MakeGroupArg(typ, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0], nil, 0),
			prog.MakeResultArg(typ.Fields[1], nil, nsec),
		})
	case g.NOutOf(1, 2):
		// Unreachable fututre for both relative and absolute
		arg = prog.MakeGroupArg(typ, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0], nil, 2e9),
			prog.MakeResultArg(typ.Fields[1], nil, 0),
		})
	default:
		// Few ms ahead for absolute.
		meta := arch.clockGettimeSyscall
		ptrArgType := meta.Args[1].(*prog.PtrType)
		argType := ptrArgType.Type.(*prog.StructType)
		tp := prog.MakeGroupArg(argType, []prog.Arg{
			prog.MakeResultArg(argType.Fields[0], nil, 0),
			prog.MakeResultArg(argType.Fields[1], nil, 0),
		})
		var tpaddr prog.Arg
		tpaddr, calls = g.Alloc(ptrArgType, tp)
		gettime := &prog.Call{
			Meta: meta,
			Args: []prog.Arg{
				prog.MakeConstArg(meta.Args[0], arch.CLOCK_REALTIME),
				tpaddr,
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		}
		calls = append(calls, gettime)
		sec := prog.MakeResultArg(typ.Fields[0], tp.Inner[0].(*prog.ResultArg), 0)
		nsec := prog.MakeResultArg(typ.Fields[1], tp.Inner[1].(*prog.ResultArg), 0)
		msec := uint64(10)
		if g.NOutOf(1, 2) {
			msec = 30
		}
		if usec {
			nsec.OpDiv = 1e3
			nsec.OpAdd = msec * 1e3
		} else {
			nsec.OpAdd = msec * 1e6
		}
		arg = prog.MakeGroupArg(typ, []prog.Arg{sec, nsec})
	}
	return
}
