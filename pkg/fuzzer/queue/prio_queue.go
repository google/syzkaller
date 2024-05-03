// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"container/heap"
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

func (p priority) next() priority {
	if len(p) == 0 {
		return p
	}
	newPrio := append([]int64{}, p...)
	newPrio[len(newPrio)-1]--
	return newPrio
}

type priorityQueueOps[T any] struct {
	impl priorityQueueImpl[T]
}

func (pq *priorityQueueOps[T]) Len() int {
	return pq.impl.Len()
}

func (pq *priorityQueueOps[T]) Push(item T, prio priority) {
	heap.Push(&pq.impl, &priorityQueueItem[T]{item, prio})
}

func (pq *priorityQueueOps[T]) Pop() T {
	if len(pq.impl) == 0 {
		var def T
		return def
	}
	return heap.Pop(&pq.impl).(*priorityQueueItem[T]).value
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
