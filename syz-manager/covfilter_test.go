// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
)

func TestCreateBitmap(t *testing.T) {
	pcs := map[uint32]uint32{
		0x81000002: 1,
		0x8120001d: 1,
	}
	target := targets.Get("test", "64")
	order := target.HostEndian
	bitmap := createCoverageBitmap(target, pcs)
	start := order.Uint32(bitmap[0:])
	size := order.Uint32(bitmap[4:])
	if start != 0x81000000 || size != 0x200020 {
		t.Fatalf("bad region 0x%x/0x%x", start, size)
	}
	for i, byte := range bitmap[8:] {
		var expect uint8
		switch i {
		case 0:
			expect = 0x1
		case 0x20001 / 0x8:
			expect = 1 << (0x20001 % 0x8)
		}
		if byte != expect {
			t.Errorf("bad bitmap byte 0x%x: 0x%x, expect 0x%x", i, byte, expect)
		}
	}
}
