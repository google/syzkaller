// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package arm64

func extractBits(from uint32, start, size uint) uint32 {
	mask := uint32((1 << size) - 1)
	return (from >> (start - size + 1)) & mask
}
