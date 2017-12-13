// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package test

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall: target.SyscallMap["mmap"],
		pageSize:    (12 - target.PtrSize) << 10,
	}

	target.PageSize = arch.pageSize
	target.DataOffset = 100 << 20
	target.MmapSyscall = arch.mmapSyscall
	target.MakeMmap = arch.makeMmap
	target.AnalyzeMmap = arch.analyzeMmap
}

type arch struct {
	mmapSyscall *prog.Syscall
	pageSize    uint64
}

func (arch *arch) makeMmap(start, npages uint64) *prog.Call {
	meta := arch.mmapSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakePointerArg(meta.Args[0], start, 0, npages, nil),
			prog.MakeConstArg(meta.Args[1], npages*arch.pageSize),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "mmap":
		npages = c.Args[1].(*prog.ConstArg).Val / arch.pageSize
		start = c.Args[0].(*prog.PointerArg).PageIndex
		mapped = true
	}
	return
}
