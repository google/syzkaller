// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/stretchr/testify/assert"
)

func TestFilterProgInfo(t *testing.T) {
	max := signal.FromRaw([]uint64{5, 6, 7}, 0)
	mask := signal.FromRaw([]uint64{2, 4, 6, 8}, 0)
	info := flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{
				Signal: []uint64{1, 2, 3, 5, 6},
				Cover:  []uint64{1, 2, 3},
			},
			{
				Signal: []uint64{2, 3, 4, 6, 7},
				Cover:  []uint64{2, 3, 4},
			},
			{
				Signal: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
		Extra: &flatrpc.CallInfo{
			Signal: []uint64{3, 4, 5},
			Cover:  []uint64{3, 4, 5},
		},
	}
	diffMaxSignal(&info, max, mask, 1, []int32{2})
	assert.Equal(t, flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{
				Signal: []uint64{1, 2, 3, 5, 6},
				Cover:  []uint64{1, 2, 3},
			},
			{
				Signal: []uint64{2, 3, 4, 6},
				Cover:  []uint64{2, 3, 4},
			},
			{
				Signal: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
		Extra: &flatrpc.CallInfo{
			Signal: []uint64{3, 4, 5},
			Cover:  []uint64{3, 4, 5},
		},
	}, info)
}
