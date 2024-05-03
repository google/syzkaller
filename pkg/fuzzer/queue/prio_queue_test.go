// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNextPriority(t *testing.T) {
	first := priority{0}
	second := first.next()
	third := second.next()
	assert.True(t, first.greaterThan(second))
	assert.True(t, second.greaterThan(third))
}

func TestPriority(t *testing.T) {
	assert.True(t, priority{1, 2}.greaterThan(priority{1, 1}))
	assert.True(t, priority{3, 2}.greaterThan(priority{2, 3}))
	assert.True(t, priority{1, -5}.greaterThan(priority{1, -10}))
	assert.True(t, priority{1}.greaterThan(priority{1, -1}))
	assert.False(t, priority{1}.greaterThan(priority{1, 1}))
	assert.True(t, priority{1, 0}.greaterThan(priority{1}))
}

func TestPrioQueueOrder(t *testing.T) {
	pq := priorityQueueOps[int]{}
	pq.Push(1, priority{1})
	pq.Push(3, priority{3})
	pq.Push(2, priority{2})

	assert.Equal(t, 3, pq.Pop())
	assert.Equal(t, 2, pq.Pop())
	assert.Equal(t, 1, pq.Pop())
	assert.Zero(t, pq.Pop())
	assert.Zero(t, pq.Len())
}
