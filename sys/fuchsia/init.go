// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuchsia

import (
	"github.com/google/syzkaller/prog"
)

func initTarget(target *prog.Target) {
	arch := &arch{}

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

// createMmapCall creates a "normal" mmap call that maps [start, start+npages) page range.
func (arch *arch) makeMmap(start, npages uint64) *prog.Call {
	return nil
}

func (arch *arch) analyzeMmap(c *prog.Call) (start, npages uint64, mapped bool) {
	return
}
