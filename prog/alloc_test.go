// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"testing"
)

func TestMemAlloc(t *testing.T) {
	t.Parallel()
	type op struct {
		addr      uint64
		size      int // if positive do noteAlloc, otherwise -- alloc
		alignment uint64
	}
	tests := [][]op{
		{
			// Just sequential allocation.
			{0, -1, 1},
			{64, -64, 1},
			{128, -65, 1},
			{256, -16, 1},
			{320, -8, 1},
		},
		{
			// First reserve some memory and then allocate.
			{0, 1, 1},
			{64, 63, 1},
			{128, 64, 1},
			{192, 65, 1},
			{320, -1, 1},
			{448, 1, 1},
			{384, -1, 1},
			{576, 1, 1},
			{640, -128, 1},
		},
		{
			// Aligned memory allocation.
			{0, -1, 1},
			{512, -1, 512},
			{1024, -1, 512},
			{128, -1, 128},
			{64, -1, 1},
			// 128 used, jumps on.
			{192, -1, 1},
			{256, -1, 1},
			{320, -1, 1},
			{384, -1, 1},
			{448, -1, 1},
			// 512 used, jumps on.
			{576, -1, 1},
			// Next 512 available at 1536.
			{1536, -1, 512},
			// Next smallest available.
			{640, -1, 1},
			// Next 64 byte aligned block.
			{1600, -512, 1},
		},
	}
	for ti, test := range tests {
		test := test
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			ma := newMemAlloc(16 << 20)
			for i, op := range test {
				if op.size > 0 {
					t.Logf("#%v: noteAlloc(%v, %v)", i, op.addr, op.size)
					ma.noteAlloc(op.addr, uint64(op.size))
					continue
				}
				t.Logf("#%v: alloc(%v) = %v", i, -op.size, op.addr)
				addr := ma.alloc(nil, uint64(-op.size), op.alignment)
				if addr != op.addr {
					t.Fatalf("bad result %v, expecting %v", addr, op.addr)
				}
			}
		})
	}
}

func TestVmaAlloc(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	r := newRand(target, randSource(t))
	va := newVmaAlloc(1000)
	for i := 0; i < 30; i++ {
		size := r.rand(4) + 1
		page := va.alloc(r, size)
		t.Logf("alloc(%v) = %3v-%3v\n", size, page, page+size)
	}
}
