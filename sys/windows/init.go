// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{
		virtualAllocSyscall:    target.SyscallMap["VirtualAlloc"],
		MEM_COMMIT:             target.ConstMap["MEM_COMMIT"],
		MEM_RESERVE:            target.ConstMap["MEM_RESERVE"],
		PAGE_EXECUTE_READWRITE: target.ConstMap["PAGE_EXECUTE_READWRITE"],
	}

	target.PageSize = pageSize
	target.DataOffset = dataOffset
	target.MmapSyscall = arch.virtualAllocSyscall
	target.MakeMmap = arch.makeMmap
	target.AnalyzeMmap = arch.analyzeMmap
}

const (
	// TODO(dvyukov): what should we do about 4k vs 64k?
	pageSize   = 4 << 10
	dataOffset = 512 << 20
)

type arch struct {
	virtualAllocSyscall *prog.Syscall

	MEM_COMMIT             uint64
	MEM_RESERVE            uint64
	PAGE_EXECUTE_READWRITE uint64
}

func (arch *arch) makeMmap(start, npages uint64) *prog.Call {
	meta := arch.virtualAllocSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakePointerArg(meta.Args[0], start, 0, npages, nil),
			prog.MakeConstArg(meta.Args[1], npages*pageSize),
			prog.MakeConstArg(meta.Args[2], arch.MEM_COMMIT|arch.MEM_RESERVE),
			prog.MakeConstArg(meta.Args[3], arch.PAGE_EXECUTE_READWRITE),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "VirtualAlloc":
		npages = c.Args[1].(*prog.ConstArg).Val / pageSize
		start = c.Args[0].(*prog.PointerArg).PageIndex
		mapped = true
	}
	return
}
