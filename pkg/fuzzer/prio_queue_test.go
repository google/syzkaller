// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestPriority(t *testing.T) {
	assert.True(t, priority{1, 2}.greaterThan(priority{1, 1}))
	assert.True(t, priority{3, 2}.greaterThan(priority{2, 3}))
	assert.True(t, priority{1, -5}.greaterThan(priority{1, -10}))
	assert.True(t, priority{1}.greaterThan(priority{1, -1}))
	assert.False(t, priority{1}.greaterThan(priority{1, 1}))
}

func TestPrioQueueOrder(t *testing.T) {
	pq := makePriorityQueue[int]()
	assert.Nil(t, pq.tryPop())

	pq.push(&priorityQueueItem[int]{value: 1, prio: priority{1}})
	pq.push(&priorityQueueItem[int]{value: 3, prio: priority{3}})
	pq.push(&priorityQueueItem[int]{value: 2, prio: priority{2}})

	assert.Equal(t, 3, pq.tryPop().value)
	assert.Equal(t, 2, pq.tryPop().value)
	assert.Equal(t, 1, pq.tryPop().value)
	assert.Nil(t, pq.tryPop())
	assert.Zero(t, pq.Len())
}

func TestPrioQueueRace(t *testing.T) {
	var eg errgroup.Group
	pq := makePriorityQueue[int]()

	// Two writers.
	for writer := 0; writer < 2; writer++ {
		eg.Go(func() error {
			for i := 0; i < 1000; i++ {
				pq.push(&priorityQueueItem[int]{value: 10, prio: priority{1}})
			}
			return nil
		})
	}
	// Two readers.
	for reader := 0; reader < 2; reader++ {
		eg.Go(func() error {
			for i := 0; i < 1000; i++ {
				pq.tryPop()
			}
			return nil
		})
	}
	eg.Wait()
}
