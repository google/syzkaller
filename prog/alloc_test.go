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
		addr uint64
		size int // if positive do noteAlloc, otherwise -- alloc
	}
	tests := [][]op{
		{
			// Just sequential allocation.
			{0, -1},
			{64, -64},
			{128, -65},
			{256, -16},
			{320, -8},
		},
		{
			// First reserve some memory and then allocate.
			{0, 1},
			{64, 63},
			{128, 64},
			{192, 65},
			{320, -1},
			{448, 1},
			{384, -1},
			{576, 1},
			{640, -128},
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
				addr := ma.alloc(nil, uint64(-op.size))
				if addr != op.addr {
					t.Fatalf("bad result %v", addr)
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
