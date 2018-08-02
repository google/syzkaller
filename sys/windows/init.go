// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"github.com/google/syzkaller/prog"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		virtualAllocSyscall:    target.SyscallMap["VirtualAlloc"],
		MEM_COMMIT:             target.ConstMap["MEM_COMMIT"],
		MEM_RESERVE:            target.ConstMap["MEM_RESERVE"],
		PAGE_EXECUTE_READWRITE: target.ConstMap["PAGE_EXECUTE_READWRITE"],
	}

	target.MakeMmap = arch.makeMmap
}

type arch struct {
	virtualAllocSyscall *prog.Syscall

	MEM_COMMIT             uint64
	MEM_RESERVE            uint64
	PAGE_EXECUTE_READWRITE uint64
}

func (arch *arch) makeMmap(addr, size uint64) *prog.Call {
	meta := arch.virtualAllocSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0], addr, size),
			prog.MakeConstArg(meta.Args[1], size),
			prog.MakeConstArg(meta.Args[2], arch.MEM_COMMIT|arch.MEM_RESERVE),
			prog.MakeConstArg(meta.Args[3], arch.PAGE_EXECUTE_READWRITE),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}
