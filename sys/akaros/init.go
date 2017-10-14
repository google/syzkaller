// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package akaros

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{
		mmapSyscall:   target.SyscallMap["mmap"],
		PROT_READ:     target.ConstMap["PROT_READ"],
		PROT_WRITE:    target.ConstMap["PROT_WRITE"],
		MAP_ANONYMOUS: target.ConstMap["MAP_ANONYMOUS"],
		MAP_PRIVATE:   target.ConstMap["MAP_PRIVATE"],
		MAP_FIXED:     target.ConstMap["MAP_FIXED"],
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
	invalidFD  = ^uint64(0)
)

type arch struct {
	mmapSyscall *prog.Syscall

	PROT_READ     uint64
	PROT_WRITE    uint64
	MAP_ANONYMOUS uint64
	MAP_PRIVATE   uint64
	MAP_FIXED     uint64
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
			prog.MakeConstArg(meta.Args[3], arch.MAP_ANONYMOUS|arch.MAP_PRIVATE|arch.MAP_FIXED),
			prog.MakeResultArg(meta.Args[4], nil, invalidFD),
			prog.MakeConstArg(meta.Args[5], 0),
		},
		Ret: prog.MakeReturnArg(meta.Ret),
	}
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	switch c.Meta.Name {
	case "mmap":
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
