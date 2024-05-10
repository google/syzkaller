// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/stretchr/testify/assert"
)

func TestFilterProgInfo(t *testing.T) {
	max := signal.FromRaw([]uint32{5, 6, 7}, 0)
	mask := signal.FromRaw([]uint32{2, 4, 6, 8}, 0)
	info := ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: []uint32{1, 2, 3, 5, 6},
				Cover:  []uint32{1, 2, 3},
			},
			{
				Signal: []uint32{2, 3, 4, 6, 7},
				Cover:  []uint32{2, 3, 4},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{3, 4, 5},
			Cover:  []uint32{3, 4, 5},
		},
	}
	diffMaxSignal(&info, max, mask, 1)
	assert.Equal(t, ipc.ProgInfo{
		Calls: []ipc.CallInfo{
			{
				Signal: []uint32{1, 2, 3},
				Cover:  []uint32{1, 2, 3},
			},
			{
				Signal: []uint32{2, 3, 4, 6},
				Cover:  []uint32{2, 3, 4},
			},
		},
		Extra: ipc.CallInfo{
			Signal: []uint32{3, 4},
			Cover:  []uint32{3, 4, 5},
		},
	}, info)
}
