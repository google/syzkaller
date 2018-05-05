// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package test

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/test/gen"
)

func init() {
	prog.RegisterTarget(gen.Target_32, initTarget)
	prog.RegisterTarget(gen.Target_64, initTarget)
}

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall: target.SyscallMap["mmap"],
	}

	target.MakeMmap = arch.makeMmap
}

type arch struct {
	mmapSyscall *prog.Syscall
}

func (arch *arch) makeMmap(addr, size uint64) *prog.Call {
	meta := arch.mmapSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0], addr, size),
			prog.MakeConstArg(meta.Args[1], size),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}
