// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"runtime"

	"github.com/google/syzkaller/prog"
)

func init() {
	lazyInit()
	target := &prog.Target{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		PtrSize:      ptrSize,
		PageSize:     pageSize,
		DataOffset:   dataOffset,
		Syscalls:     syscalls,
		Resources:    resources,
		MakeMmap:     makeMmap,
		AnalyzeMmap:  analyzeMmap,
		SanitizeCall: sanitizeCall,
		SpecialStructs: map[string]func(g *prog.Gen, typ *prog.StructType, old *prog.GroupArg) (prog.Arg, []*prog.Call){
			"timespec": generateTimespec,
			"timeval":  generateTimespec,
		},
		StringDictionary: stringDictionary,
	}
	prog.RegisterTarget(target)
}

const (
	// TODO(dvyukov): dehardcode
	ptrSize    = 8
	pageSize   = 4 << 10
	dataOffset = 512 << 20
	invalidFD  = ^uint64(0)
)

var (
	mmapSyscall         *prog.Syscall
	clockGettimeSyscall *prog.Syscall

	stringDictionary = []string{"user", "keyring", "trusted", "system", "security", "selinux",
		"posix_acl_access", "mime_type", "md5sum", "nodev", "self",
		"bdev", "proc", "cgroup", "cpuset",
		"lo", "eth0", "eth1", "em0", "em1", "wlan0", "wlan1", "ppp0", "ppp1",
		"vboxnet0", "vboxnet1", "vmnet0", "vmnet1", "GPL"}
)

// createMmapCall creates a "normal" mmap call that maps [start, start+npages) page range.
func makeMmap(start, npages uint64) *prog.Call {
	return &prog.Call{
		Meta: mmapSyscall,
		Args: []prog.Arg{
			prog.MakePointerArg(mmapSyscall.Args[0], start, 0, npages, nil),
			prog.MakeConstArg(mmapSyscall.Args[1], npages*pageSize),
			prog.MakeConstArg(mmapSyscall.Args[2], PROT_READ|PROT_WRITE),
			prog.MakeConstArg(mmapSyscall.Args[3], MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED),
			prog.MakeResultArg(mmapSyscall.Args[4], nil, invalidFD),
			prog.MakeConstArg(mmapSyscall.Args[5], 0),
		},
		Ret: prog.MakeReturnArg(mmapSyscall.Ret),
	}
}

func analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		npages = c.Args[1].(*prog.ConstArg).Val / pageSize
		if npages == 0 {
			return
		}
		flags := c.Args[3].(*prog.ConstArg).Val
		fd := c.Args[4].(*prog.ResultArg).Val
		if flags&MAP_ANONYMOUS == 0 && fd == invalidFD {
			return
		}
		start = c.Args[0].(*prog.PointerArg).PageIndex
		mapped = true
		return
	case "munmap":
		start = c.Args[0].(*prog.PointerArg).PageIndex
		npages = c.Args[1].(*prog.ConstArg).Val / pageSize
		mapped = false
		return
	case "mremap":
		start = c.Args[4].(*prog.PointerArg).PageIndex
		npages = c.Args[2].(*prog.ConstArg).Val / pageSize
		mapped = true
		return
	default:
		return
	}
}

func sanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= MAP_FIXED
	case "mremap":
		// Add MREMAP_FIXED flag, otherwise it produces non-deterministic results.
		flags := c.Args[3].(*prog.ConstArg)
		if flags.Val&MREMAP_MAYMOVE != 0 {
			flags.Val |= MREMAP_FIXED
		}
	case "mknod", "mknodat":
		pos := 1
		if c.Meta.CallName == "mknodat" {
			pos = 2
		}
		mode := c.Args[pos].(*prog.ConstArg)
		dev := c.Args[pos+1].(*prog.ConstArg)
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		// TODO: not required if executor drops privileges.
		switch mode.Val & (S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK) {
		case S_IFREG, S_IFIFO, S_IFSOCK:
		case S_IFBLK:
			if dev.Val>>8 == 7 {
				break // loop
			}
			mode.Val &^= S_IFBLK
			mode.Val |= S_IFREG
		case S_IFCHR:
			mode.Val &^= S_IFCHR
			mode.Val |= S_IFREG
		}
	case "syslog":
		cmd := c.Args[0].(*prog.ConstArg)
		// These disable console output, but we need it.
		if cmd.Val == SYSLOG_ACTION_CONSOLE_OFF || cmd.Val == SYSLOG_ACTION_CONSOLE_ON {
			cmd.Val = SYSLOG_ACTION_SIZE_UNREAD
		}
	case "ioctl":
		cmd := c.Args[1].(*prog.ConstArg)
		// Freeze kills machine. Though, it is an interesting functions,
		// so we need to test it somehow.
		// TODO: not required if executor drops privileges.
		if uint32(cmd.Val) == FIFREEZE {
			cmd.Val = FITHAW
		}
	case "ptrace":
		req := c.Args[0].(*prog.ConstArg)
		// PTRACE_TRACEME leads to unkillable processes, see:
		// https://groups.google.com/forum/#!topic/syzkaller/uGzwvhlCXAw
		if req.Val == PTRACE_TRACEME {
			req.Val = ^uint64(0)
		}
	case "exit", "exit_group":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}

func generateTimespec(g *prog.Gen, typ *prog.StructType, old *prog.GroupArg) (arg prog.Arg, calls []*prog.Call) {
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
		meta := clockGettimeSyscall
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
				prog.MakeConstArg(meta.Args[0], CLOCK_REALTIME),
				tpaddr,
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		}
		calls = append(calls, gettime)
		sec := prog.MakeResultArg(typ.Fields[0], tp.(*prog.GroupArg).Inner[0], 0)
		nsec := prog.MakeResultArg(typ.Fields[1], tp.(*prog.GroupArg).Inner[1], 0)
		msec := uint64(10)
		if g.NOutOf(1, 2) {
			msec = 30
		}
		if usec {
			nsec.(*prog.ResultArg).OpDiv = 1e3
			nsec.(*prog.ResultArg).OpAdd = msec * 1e3
		} else {
			nsec.(*prog.ResultArg).OpAdd = msec * 1e6
		}
		arg = prog.MakeGroupArg(typ, []prog.Arg{sec, nsec})
	}
	return
}

func lazyInit() {
	resourceMap := make(map[string]*prog.ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}

	keyedStructs := make(map[prog.StructKey]*prog.StructDesc)
	for _, desc := range structDescs {
		keyedStructs[desc.Key] = desc.Desc
	}
	structDescs = nil

	for _, c := range syscalls {
		prog.ForeachType(c, func(t0 prog.Type) {
			switch t := t0.(type) {
			case *prog.ResourceType:
				t.Desc = resourceMap[t.TypeName]
				if t.Desc == nil {
					panic("no resource desc")
				}
			case *prog.StructType:
				t.StructDesc = keyedStructs[t.Key]
				if t.StructDesc == nil {
					panic("no struct desc")
				}
			case *prog.UnionType:
				t.StructDesc = keyedStructs[t.Key]
				if t.StructDesc == nil {
					panic("no union desc")
				}
			}
		})
		switch c.Name {
		case "mmap":
			mmapSyscall = c
		case "clock_gettime":
			clockGettimeSyscall = c
		}
	}
}
