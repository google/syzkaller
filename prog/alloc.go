// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

// memAlloc keeps track of allocated objects in a program
// and decides where to allocate new objects.
// It has 2 main methods: noteAlloc which is called for existing allocations
// in a program as we analyze it; and alloc which decides where to allocate
// a new object.
// The implementation is based on a 2-level bitmap where each bit represents
// 64 bytes (memAllocGranule) of program memory.
type memAlloc struct {
	size uint64
	mem  [memAllocL1Size]*[memAllocL0Size]uint64
	buf  [memAllocL0Size]uint64
}

const (
	memAllocGranule = 64 // 1 bit per that many bytes (all allocations are rounded to this size)
	memAllocMaxMem  = 16 << 20
	memAllocL0Size  = 64
	bitsPerUint64   = 8 * 8
	memAllocL0Mem   = memAllocL0Size * memAllocGranule * bitsPerUint64
	memAllocL1Size  = memAllocMaxMem / memAllocL0Mem
)

func newMemAlloc(totalMemSize uint64) *memAlloc {
	if totalMemSize > memAllocMaxMem {
		panic(fmt.Sprintf("newMemAlloc: too much mem %v (max: %v)", totalMemSize, memAllocMaxMem))
	}
	if totalMemSize%memAllocL0Mem != 0 {
		panic(fmt.Sprintf("newMemAlloc: unaligned size %v (align: %v)", totalMemSize, memAllocL0Mem))
	}
	ma := &memAlloc{
		size: totalMemSize / memAllocGranule,
	}
	ma.mem[0] = &ma.buf
	return ma
}

func (ma *memAlloc) noteAlloc(addr0, size0 uint64) {
	addr := addr0 / memAllocGranule
	size := (addr0+size0+memAllocGranule-1)/memAllocGranule - addr
	for i := uint64(0); i < size; i++ {
		ma.set(addr + i)
	}
}

// alloc returns the next free address of size0 with respect to the given alignment.
func (ma *memAlloc) alloc(r *randGen, size0, alignment0 uint64) uint64 {
	if size0 == 0 {
		size0 = 1
	}
	if alignment0 == 0 {
		alignment0 = 1
	}
	size := (size0 + memAllocGranule - 1) / memAllocGranule
	alignment := (alignment0 + memAllocGranule - 1) / memAllocGranule
	end := ma.size - size
	for start := uint64(0); start <= end; start += alignment {
		empty := true
		for i := uint64(0); i < size; i++ {
			if ma.get(start + i) {
				empty = false
				break
			}
		}
		if empty {
			start0 := start * memAllocGranule
			ma.noteAlloc(start0, size0)
			return start0
		}
	}
	ma.bankruptcy()
	return ma.alloc(r, size0, alignment0)
}

func (ma *memAlloc) bankruptcy() {
	for i1 := uint64(0); i1 < ma.size/(memAllocL0Size*bitsPerUint64); i1++ {
		if ma.mem[i1] == nil {
			continue
		}
		for i0 := range ma.mem[i1] {
			ma.mem[i1][i0] = 0
		}
	}
}

func (ma *memAlloc) pos(idx uint64) (i1, i0, bit uint64) {
	i1 = idx / (memAllocL0Size * bitsPerUint64)
	r1 := idx % (memAllocL0Size * bitsPerUint64)
	i0 = r1 / bitsPerUint64
	bit = 1 << (r1 % bitsPerUint64)
	return
}

func (ma *memAlloc) set(idx uint64) {
	i1, i0, bit := ma.pos(idx)
	if ma.mem[i1] == nil {
		ma.mem[i1] = new([memAllocL0Size]uint64)
	}
	ma.mem[i1][i0] |= bit
}

func (ma *memAlloc) get(idx uint64) bool {
	i1, i0, bit := ma.pos(idx)
	if ma.mem[i1] == nil {
		return false
	}
	return ma.mem[i1][i0]&bit != 0
}

type vmaAlloc struct {
	numPages uint64
	used     []uint64
	m        map[uint64]struct{}
}

func newVmaAlloc(totalPages uint64) *vmaAlloc {
	return &vmaAlloc{
		numPages: totalPages,
		m:        make(map[uint64]struct{}),
	}
}

func (va *vmaAlloc) noteAlloc(page, size uint64) {
	for i := page; i < page+size; i++ {
		if _, ok := va.m[i]; ok {
			continue
		}
		va.m[i] = struct{}{}
		va.used = append(va.used, i)
	}
}

func (va *vmaAlloc) alloc(r *randGen, size uint64) uint64 {
	if size > va.numPages {
		panic(fmt.Sprintf("vmaAlloc: bad size=%v numPages=%v", size, va.numPages))
	}
	var page uint64
	if len(va.used) == 0 || r.oneOf(5) {
		page = r.rand(4)
		if !r.oneOf(100) {
			page = va.numPages - page - size
		}
	} else {
		page = va.used[r.rand(len(va.used))]
		if size > 1 && r.bin() {
			off := r.rand(int(size))
			if off > page {
				off = page
			}
			page -= off
		}
		if page+size > va.numPages {
			page = va.numPages - size
		}
	}
	if page >= va.numPages || size > va.numPages || page+size > va.numPages {
		panic(fmt.Sprintf("vmaAlloc: bad page=%v size=%v numPages=%v", page, size, va.numPages))
	}
	va.noteAlloc(page, size)
	return page
}
