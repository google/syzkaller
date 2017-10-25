// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package freebsd

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall: target.SyscallMap["mmap"],
		PROT_READ:   target.ConstMap["PROT_READ"],
		PROT_WRITE:  target.ConstMap["PROT_WRITE"],
		MAP_ANON:    target.ConstMap["MAP_ANON"],
		MAP_PRIVATE: target.ConstMap["MAP_PRIVATE"],
		MAP_FIXED:   target.ConstMap["MAP_FIXED"],
		S_IFREG:     target.ConstMap["S_IFREG"],
		S_IFCHR:     target.ConstMap["S_IFCHR"],
		S_IFBLK:     target.ConstMap["S_IFBLK"],
		S_IFIFO:     target.ConstMap["S_IFIFO"],
		S_IFSOCK:    target.ConstMap["S_IFSOCK"],
	}

	target.PageSize = pageSize
	target.DataOffset = dataOffset
	target.MmapSyscall = arch.mmapSyscall
	target.MakeMmap = arch.makeMmap
	target.AnalyzeMmap = arch.analyzeMmap
	target.SanitizeCall = arch.sanitizeCall
}

const (
	pageSize   = 4 << 10
	dataOffset = 512 << 20
	invalidFD  = ^uint64(0)
)

type arch struct {
	mmapSyscall         *prog.Syscall
	clockGettimeSyscall *prog.Syscall

	PROT_READ   uint64
	PROT_WRITE  uint64
	MAP_ANON    uint64
	MAP_PRIVATE uint64
	MAP_FIXED   uint64
	S_IFREG     uint64
	S_IFCHR     uint64
	S_IFBLK     uint64
	S_IFIFO     uint64
	S_IFSOCK    uint64
}

// createMmapCall creates a "normal" mmap call that maps [start, start+npages) page range.
func (arch *arch) makeMmap(start, npages uint64) *prog.Call {
	meta := arch.mmapSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakePointerArg(meta.Args[0], start, 0, npages, nil),
			prog.MakeConstArg(meta.Args[1], npages*pageSize),
			prog.MakeConstArg(meta.Args[2], arch.PROT_READ|arch.PROT_WRITE),
			prog.MakeConstArg(meta.Args[3], arch.MAP_ANON|arch.MAP_PRIVATE|arch.MAP_FIXED),
			prog.MakeResultArg(meta.Args[4], nil, invalidFD),
			prog.MakeConstArg(meta.Args[5], 0),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		npages = c.Args[1].(*prog.ConstArg).Val / pageSize
		if npages == 0 {
			return
		}
		flags := c.Args[3].(*prog.ConstArg).Val
		fd := c.Args[4].(*prog.ResultArg).Val
		if flags&arch.MAP_ANON == 0 && fd == invalidFD {
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
	default:
		return
	}
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknodat":
		pos := 1
		if c.Meta.CallName == "mknodat" {
			pos = 2
		}
		mode := c.Args[pos].(*prog.ConstArg)
		dev := c.Args[pos+1].(*prog.ConstArg)
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		// TODO: not required if executor drops privileges.
		switch mode.Val & (arch.S_IFREG | arch.S_IFCHR | arch.S_IFBLK | arch.S_IFIFO | arch.S_IFSOCK) {
		case arch.S_IFREG, arch.S_IFIFO, arch.S_IFSOCK:
		case arch.S_IFBLK:
			// TODO(dvyukov): mknod dev argument is uint32,
			// but prog arguments contain not-truncated uint64 values,
			// so we can mistakenly assume that this is not loop, when it actually is.
			// This is not very harmful, but need to verify other arguments in this function.
			if dev.Val>>8 == 7 {
				break // loop
			}
			mode.Val &^= arch.S_IFBLK
			mode.Val |= arch.S_IFREG
		case arch.S_IFCHR:
			mode.Val &^= arch.S_IFCHR
			mode.Val |= arch.S_IFREG
		}
	case "exit":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
