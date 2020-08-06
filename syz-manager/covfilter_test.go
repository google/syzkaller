// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
)

func TestCreateBitmap(t *testing.T) {
	target := targets.Get("test", "64")
	filter := &CoverFilter{
		weightedPCs: make(map[uint32]uint32),
		target:      target,
	}
	enablePCStart := uint32(0x81000002)
	enablePCEnd := uint32(0x8120001d)
	filter.weightedPCs[enablePCStart] = 1
	filter.weightedPCs[enablePCEnd] = 1

	filter.detectRegion()
	if filter.pcStart != 0x81000000 ||
		filter.pcEnd != 0x81200020 ||
		filter.pcSize != 0x200020 {
		t.Fatalf("filte.detectReigion test failed %x %x %x",
			filter.pcStart, filter.pcEnd, filter.pcSize)
	}
	bitmap := filter.bitmapBytes()
	bitmap = bitmap[8:]
	for i, byte := range bitmap {
		if i == 0 {
			if byte != 0x1 {
				t.Fatalf("filter.bitmapByte enable PC failed")
			}
		} else if i == (0x20001 / 0x8) {
			if byte != byte&(1<<(0x20001%0x8)) {
				t.Fatalf("filter.bitmapByte enable PC failed")
			}
		} else {
			if byte != 0x0 {
				t.Fatalf("filter.bitmapByte disable PC failed")
			}
		}
	}
}
