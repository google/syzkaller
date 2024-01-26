// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/stretchr/testify/assert"
)

func TestTriagePrio(t *testing.T) {
	wq := newWorkQueue(6, make(chan struct{}))
	first := &WorkTriage{info: ipc.CallInfo{Signal: make([]uint32, 10)}}
	wq.enqueue(first)
	second := &WorkTriage{info: ipc.CallInfo{Signal: make([]uint32, 20)}}
	wq.enqueue(second)
	third := &WorkTriage{info: ipc.CallInfo{Signal: make([]uint32, 5)}}
	wq.enqueue(third)
	// The order of decreasing the new signal.
	assert.Equal(t, second, wq.dequeue())
	assert.Equal(t, first, wq.dequeue())
	assert.Equal(t, third, wq.dequeue())
}
