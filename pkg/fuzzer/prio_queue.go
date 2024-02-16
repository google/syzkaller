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
	return false
}

type priorityQueue[T any] struct {
	impl priorityQueueImpl[T]
	c    *sync.Cond
}

func makePriorityQueue[T any]() *priorityQueue[T] {
	return &priorityQueue[T]{
		c: sync.NewCond(&sync.Mutex{}),
	}
}

func (pq *priorityQueue[T]) Len() int {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	return pq.impl.Len()
}

func (pq *priorityQueue[T]) push(item *priorityQueueItem[T]) {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	heap.Push(&pq.impl, item)
	pq.c.Signal()
}

// pop() blocks until there's input.
func (pq *priorityQueue[T]) pop() *priorityQueueItem[T] {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	for pq.impl.Len() == 0 {
		pq.c.Wait()
	}
	return heap.Pop(&pq.impl).(*priorityQueueItem[T])
}

func (pq *priorityQueue[T]) tryPop() *priorityQueueItem[T] {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
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
