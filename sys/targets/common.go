// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"github.com/google/syzkaller/prog"
)

// MakePosixMmap creates a "normal" posix mmap call that maps the target data range.
// If exec is set, the mapping is mapped as PROT_EXEC.
// If contain is set, the mapping is surrounded by PROT_NONE pages.
// These flags should be in sync with what executor.
func MakePosixMmap(target *prog.Target, exec, contain bool) func() []*prog.Call {
	meta := target.SyscallMap["mmap"]
	protRW := target.GetConst("PROT_READ") | target.GetConst("PROT_WRITE")
	if exec {
		protRW |= target.GetConst("PROT_EXEC")
	}
	flags := target.GetConst("MAP_ANONYMOUS") | target.GetConst("MAP_PRIVATE") | target.GetConst("MAP_FIXED")
	size := target.NumPages * target.PageSize
	const invalidFD = ^uint64(0)
	makeMmap := func(addr, size, prot uint64) *prog.Call {
		args := []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, addr, size),
			prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
			prog.MakeConstArg(meta.Args[2].Type, prog.DirIn, prot),
			prog.MakeConstArg(meta.Args[3].Type, prog.DirIn, flags),
			prog.MakeResultArg(meta.Args[4].Type, prog.DirIn, nil, invalidFD),
		}
		i := len(args)
		// Some targets have a padding argument between fd and offset.
		if len(meta.Args) > 6 {
			args = append(args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
			i++
		}
		args = append(args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
		return &prog.Call{
			Meta: meta,
			Args: args,
			Ret:  prog.MakeReturnArg(meta.Ret),
		}
	}
	return func() []*prog.Call {
		if contain {
			return []*prog.Call{
				makeMmap(^target.PageSize+1, target.PageSize, 0),
				makeMmap(0, size, protRW),
				makeMmap(size, target.PageSize, 0),
			}
		}
		return []*prog.Call{makeMmap(0, size, protRW)}
	}
}

func MakeSyzMmap(target *prog.Target) func() []*prog.Call {
	meta := target.SyscallMap["syz_mmap"]
	size := target.NumPages * target.PageSize
	return func() []*prog.Call {
		return []*prog.Call{
			{
				Meta: meta,
				Args: []prog.Arg{
					prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, 0, size),
					prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
				},
				Ret: prog.MakeReturnArg(meta.Ret),
			},
		}
	}
}

type UnixNeutralizer struct {
	MAP_FIXED uint64
	S_IFREG   uint64
	S_IFCHR   uint64
	S_IFBLK   uint64
	S_IFIFO   uint64
	S_IFSOCK  uint64
}

func MakeUnixNeutralizer(target *prog.Target) *UnixNeutralizer {
	return &UnixNeutralizer{
		MAP_FIXED: target.GetConst("MAP_FIXED"),
		S_IFREG:   target.GetConst("S_IFREG"),
		S_IFCHR:   target.GetConst("S_IFCHR"),
		S_IFBLK:   target.GetConst("S_IFBLK"),
		S_IFIFO:   target.GetConst("S_IFIFO"),
		S_IFSOCK:  target.GetConst("S_IFSOCK"),
	}
}

func (arch *UnixNeutralizer) Neutralize(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknodat":
		pos := 1
		if c.Meta.CallName == "mknodat" {
			pos = 2
		}
		switch c.Args[pos+1].Type().(type) {
		case *prog.ProcType, *prog.ResourceType:
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
		// This code is reserved by executor.
		if code.Val%128 == 67 {
			code.Val = 1
		}
	}
}
