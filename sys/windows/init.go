// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"github.com/google/syzkaller/prog"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		target:                 target,
		virtualAllocSyscall:    target.SyscallMap["VirtualAlloc"],
		MEM_COMMIT:             target.GetConst("MEM_COMMIT"),
		MEM_RESERVE:            target.GetConst("MEM_RESERVE"),
		PAGE_EXECUTE_READWRITE: target.GetConst("PAGE_EXECUTE_READWRITE"),
	}

	target.MakeDataMmap = arch.makeMmap
}

type arch struct {
	target              *prog.Target
	virtualAllocSyscall *prog.Syscall

	MEM_COMMIT             uint64
	MEM_RESERVE            uint64
	PAGE_EXECUTE_READWRITE uint64
}

func (arch *arch) makeMmap() []*prog.Call {
	meta := arch.virtualAllocSyscall
	size := arch.target.NumPages * arch.target.PageSize
	return []*prog.Call{
		{
			Meta: meta,
			Args: []prog.Arg{
				prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, 0, size),
				prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
				prog.MakeConstArg(meta.Args[2].Type, prog.DirIn, arch.MEM_COMMIT|arch.MEM_RESERVE),
				prog.MakeConstArg(meta.Args[3].Type, prog.DirIn, arch.PAGE_EXECUTE_READWRITE),
			},
			Ret: prog.MakeReturnArg(meta.Ret),
		},
	}
}
