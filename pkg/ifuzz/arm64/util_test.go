// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package arm64

import (
	"testing"
)

func extractBitsOne(t *testing.T, from uint32, start, size uint, expect uint32) {
	ret := extractBits(from, start, size)
	if ret != expect {
		t.Fatalf("extractBits(%x, %d, %d) returned %x instead of %x", from, start, size, ret, expect)
	}
}

func TestExtractBits(t *testing.T) {
	extractBitsOne(t, 0, 0, 0, 0)
	extractBitsOne(t, 0xffffffff, 0, 0, 0)
	for i := uint(0); i <= 31; i++ {
		extractBitsOne(t, 0xffffffff, i, 1, 1)
	}
	extractBitsOne(t, 0xf0f0f0f0, 31, 5, 0b11110)
	extractBitsOne(t, 0xf0f0f0f0, 25, 4, 0b0011)
	extractBitsOne(t, 0xf0f0f0f0, 21, 4, 0b1100)
}
