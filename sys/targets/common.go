// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"github.com/google/syzkaller/prog"
)

// MakePosixMmap creates a "normal" posix mmap call that maps [addr, addr+size) range.
func MakePosixMmap(target *prog.Target) func(addr, size uint64) *prog.Call {
	meta := target.SyscallMap["mmap"]
	prot := target.ConstMap["PROT_READ"] | target.ConstMap["PROT_WRITE"]
	flags := target.ConstMap["MAP_ANONYMOUS"] | target.ConstMap["MAP_PRIVATE"] | target.ConstMap["MAP_FIXED"]
	const invalidFD = ^uint64(0)
	return func(addr, size uint64) *prog.Call {
		return &prog.Call{
			Meta: meta,
			Args: []prog.Arg{
				prog.MakeVmaPointerArg(meta.Args[0], addr, size),
				prog.MakeConstArg(meta.Args[1], size),
				prog.MakeConstArg(meta.Args[2], prot),
				prog.MakeConstArg(meta.Args[3], flags),
				prog.MakeResultArg(meta.Args[4], nil, invalidFD),
				prog.MakeConstArg(meta.Args[5], 0),
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		}
	}
}

func MakeSyzMmap(target *prog.Target) func(addr, size uint64) *prog.Call {
	meta := target.SyscallMap["syz_mmap"]
	return func(addr, size uint64) *prog.Call {
		return &prog.Call{
			Meta: meta,
			Args: []prog.Arg{
				prog.MakeVmaPointerArg(meta.Args[0], addr, size),
				prog.MakeConstArg(meta.Args[1], size),
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		}
	}
}

type UnixSanitizer struct {
	MAP_FIXED      uint64
	MREMAP_MAYMOVE uint64
	MREMAP_FIXED   uint64
	S_IFREG        uint64
	S_IFCHR        uint64
	S_IFBLK        uint64
	S_IFIFO        uint64
	S_IFSOCK       uint64
}

func MakeUnixSanitizer(target *prog.Target) *UnixSanitizer {
	return &UnixSanitizer{
		MAP_FIXED:      target.ConstMap["MAP_FIXED"],
		MREMAP_MAYMOVE: target.ConstMap["MREMAP_MAYMOVE"],
		MREMAP_FIXED:   target.ConstMap["MREMAP_FIXED"],
		S_IFREG:        target.ConstMap["S_IFREG"],
		S_IFCHR:        target.ConstMap["S_IFCHR"],
		S_IFBLK:        target.ConstMap["S_IFBLK"],
		S_IFIFO:        target.ConstMap["S_IFIFO"],
		S_IFSOCK:       target.ConstMap["S_IFSOCK"],
	}
}

func (arch *UnixSanitizer) SanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mremap":
		// Add MREMAP_FIXED flag, otherwise it produces non-deterministic results.
		flags := c.Args[3].(*prog.ConstArg)
		if flags.Val&arch.MREMAP_MAYMOVE != 0 {
			flags.Val |= arch.MREMAP_FIXED
		}
	case "mknod", "mknodat":
		pos := 1
		if c.Meta.CallName == "mknodat" {
			pos = 2
		}
		if _, ok := c.Args[pos+1].Type().(*prog.ProcType); ok {
			return
		}
		mode := c.Args[pos].(*prog.ConstArg)
		dev := c.Args[pos+1].(*prog.ConstArg)
		dev.Val = uint64(uint32(dev.Val))
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		// TODO: not required if executor drops privileges.
		mask := arch.S_IFREG | arch.S_IFCHR | arch.S_IFBLK | arch.S_IFIFO | arch.S_IFSOCK
		switch mode.Val & mask {
		case arch.S_IFREG, arch.S_IFIFO, arch.S_IFSOCK:
		case arch.S_IFBLK:
			if dev.Val>>8 == 7 {
				break // loop
			}
			mode.Val &^= arch.S_IFBLK
			mode.Val |= arch.S_IFREG
		case arch.S_IFCHR:
			mode.Val &^= arch.S_IFCHR
			mode.Val |= arch.S_IFREG
		}
	case "exit", "exit_group":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
