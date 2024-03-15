// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/stretchr/testify/assert"
)

// nolint: dupl
func TestFilterProgInfo(t *testing.T) {
	mask := signal.FromRaw([]uint32{2, 4, 6, 8}, 0)
	info := ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: []uint32{1, 2, 3},
				Cover:  []uint32{1, 2, 3},
			},
			{
				Signal: []uint32{2, 3, 4},
				Cover:  []uint32{2, 3, 4},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{3, 4, 5},
			Cover:  []uint32{3, 4, 5},
		},
	}
	filterProgInfo(&info, mask)
	assert.Equal(t, ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: []uint32{2},
				Cover:  []uint32{1, 2, 3},
			},
			{
				Signal: []uint32{2, 4},
				Cover:  []uint32{2, 3, 4},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{4},
			Cover:  []uint32{3, 4, 5},
		},
	}, info)
}

// nolint: dupl
func TestDiffProgInfo(t *testing.T) {
	base := signal.FromRaw([]uint32{0, 1, 2}, 0)
	info := ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: []uint32{0, 1, 2},
				Cover:  []uint32{0, 1, 2},
			},
			{
				Signal: []uint32{1, 2, 3},
				Cover:  []uint32{1, 2, 3},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{2, 3, 4},
			Cover:  []uint32{2, 3, 4},
		},
	}
	diffProgInfo(&info, base)
	assert.Equal(t, ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: nil,
				Cover:  []uint32{0, 1, 2},
			},
			{
				Signal: []uint32{3},
				Cover:  []uint32{1, 2, 3},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{3, 4},
			Cover:  []uint32{2, 3, 4},
		},
	}, info)
}
