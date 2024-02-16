// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPriority(t *testing.T) {
	assert.True(t, priority{1, 2}.greaterThan(priority{1, 1}))
	assert.True(t, priority{3, 2}.greaterThan(priority{2, 3}))
	assert.True(t, priority{1, -5}.greaterThan(priority{1, -10}))
}

func TestPrioQueueOrder(t *testing.T) {
	pq := makePriorityQueue[int]()
	pq.push(&priorityQueueItem[int]{value: 1, prio: priority{1}})
	pq.push(&priorityQueueItem[int]{value: 3, prio: priority{3}})
	pq.push(&priorityQueueItem[int]{value: 2, prio: priority{2}})

	assert.Equal(t, 3, pq.pop().value)
	assert.Equal(t, 2, pq.pop().value)
	assert.Equal(t, 1, pq.pop().value)
	assert.Nil(t, pq.tryPop())
}

func TestPrioQueueWait(t *testing.T) {
	var wg sync.WaitGroup
	pq := makePriorityQueue[int]()
	assert.Nil(t, pq.tryPop())

	wg.Add(1)
	go func() {
		assert.Equal(t, 10, pq.pop().value)
		wg.Done()
	}()

	pq.push(&priorityQueueItem[int]{value: 10, prio: priority{1}})
	wg.Wait()
}
