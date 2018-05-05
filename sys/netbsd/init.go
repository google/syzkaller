// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package netbsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/netbsd/gen"
)

func init() {
	prog.RegisterTarget(gen.Target_amd64, initTarget)
}

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall:   target.SyscallMap["mmap"],
		PROT_READ:     target.ConstMap["PROT_READ"],
		PROT_WRITE:    target.ConstMap["PROT_WRITE"],
		MAP_ANONYMOUS: target.ConstMap["MAP_ANON"],
		MAP_PRIVATE:   target.ConstMap["MAP_PRIVATE"],
		MAP_FIXED:     target.ConstMap["MAP_FIXED"],
	}

	target.MakeMmap = arch.makeMmap
	target.SanitizeCall = arch.sanitizeCall
}

const (
	invalidFD = ^uint64(0)
)

type arch struct {
	mmapSyscall *prog.Syscall

	PROT_READ     uint64
	PROT_WRITE    uint64
	MAP_ANONYMOUS uint64
	MAP_PRIVATE   uint64
	MAP_FIXED     uint64
}

func (arch *arch) makeMmap(addr, size uint64) *prog.Call {
	meta := arch.mmapSyscall
	return &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0], addr, size),
			prog.MakeConstArg(meta.Args[1], size),
			prog.MakeConstArg(meta.Args[2], arch.PROT_READ|arch.PROT_WRITE),
			prog.MakeConstArg(meta.Args[3], arch.MAP_ANONYMOUS|arch.MAP_PRIVATE|arch.MAP_FIXED),
			prog.MakeResultArg(meta.Args[4], nil, invalidFD),
			prog.MakeConstArg(meta.Args[5], 0),
			prog.MakeConstArg(meta.Args[6], 0),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknodat":
		break
	case "exit":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
