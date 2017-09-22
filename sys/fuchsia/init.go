// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuchsia

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall: target.SyscallMap["syz_mmap"],
	}

	target.PageSize = pageSize
	target.DataOffset = dataOffset
	target.MmapSyscall = arch.mmapSyscall
	target.MakeMmap = arch.makeMmap
	target.AnalyzeMmap = arch.analyzeMmap
}

const (
	pageSize   = 4 << 10
	dataOffset = 512 << 20
)

type arch struct {
	mmapSyscall *prog.Syscall
}

func (arch *arch) makeMmap(start, npages uint64) *prog.Call {
	meta := arch.mmapSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakePointerArg(meta.Args[0], start, 0, npages, nil),
			prog.MakeConstArg(meta.Args[1], npages*pageSize),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "syz_mmap":
		npages = c.Args[1].(*prog.ConstArg).Val / pageSize
		start = c.Args[0].(*prog.PointerArg).PageIndex
		mapped = true
	}
	return
}
