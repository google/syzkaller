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
