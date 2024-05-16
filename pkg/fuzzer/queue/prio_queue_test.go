// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrioQueueOrder(t *testing.T) {
	pq := priorityQueueOps[int]{}
	pq.Push(1, 1)
	pq.Push(3, 3)
	pq.Push(2, 2)

	assert.Equal(t, 1, pq.Pop())
	assert.Equal(t, 2, pq.Pop())
	assert.Equal(t, 3, pq.Pop())
	assert.Zero(t, pq.Pop())
	assert.Zero(t, pq.Len())
}
