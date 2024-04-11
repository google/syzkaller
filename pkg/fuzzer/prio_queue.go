// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"container/heap"
	"sync"
)

type priority []int64

func (p priority) greaterThan(other priority) bool {
	for i := range p {
		if i >= len(other) || p[i] > other[i] {
			return true
		}
		if p[i] < other[i] {
			return false
		}
	}
	for i := len(p); i < len(other); i++ {
		if other[i] < 0 {
			return true
		}
		if other[i] > 0 {
			return false
		}
	}
	return false
}

type priorityQueue[T any] struct {
	impl priorityQueueImpl[T]
	mu   sync.RWMutex
}

func makePriorityQueue[T any]() *priorityQueue[T] {
	return &priorityQueue[T]{}
}

func (pq *priorityQueue[T]) Len() int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	return pq.impl.Len()
}

func (pq *priorityQueue[T]) push(item *priorityQueueItem[T]) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	heap.Push(&pq.impl, item)
}

func (pq *priorityQueue[T]) tryPop() *priorityQueueItem[T] {
	if !pq.mu.TryLock() {
		return nil
	}
	defer pq.mu.Unlock()
	return pq.popLocked()
}

func (pq *priorityQueue[T]) pop() *priorityQueueItem[T] {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.popLocked()
}

func (pq *priorityQueue[T]) popLocked() *priorityQueueItem[T] {
	if len(pq.impl) == 0 {
		return nil
	}
	return heap.Pop(&pq.impl).(*priorityQueueItem[T])
}

// The implementation below is based on the example provided
// by https://pkg.go.dev/container/heap.

type priorityQueueItem[T any] struct {
	value T
	prio  priority
}

type priorityQueueImpl[T any] []*priorityQueueItem[T]

func (pq priorityQueueImpl[T]) Len() int { return len(pq) }

func (pq priorityQueueImpl[T]) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest,
	// priority so we use greater than here.
	return pq[i].prio.greaterThan(pq[j].prio)
}

func (pq priorityQueueImpl[T]) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *priorityQueueImpl[T]) Push(x any) {
	*pq = append(*pq, x.(*priorityQueueItem[T]))
}

func (pq *priorityQueueImpl[T]) Pop() any {
	n := len(*pq)
	item := (*pq)[n-1]
	(*pq)[n-1] = nil
	*pq = (*pq)[:n-1]
	return item
}
