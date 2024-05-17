// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type EnvDescr int64

const (
	AnyEnvironment EnvDescr = iota
	NewEnvironment
	// TODO: add CleanVMEnvironment support.

	EnvironmentsCount
)

// ExecTask is the atomic analysis entity. Once executed, it could trigger the
// pipeline propagation for the program.
type ExecTask struct {
	CreationTime   time.Time
	Program        *prog.Prog
	ID             int64
	ExecResultChan ExecResultChan

	priority int // The priority of the item in the queue.
	// The index is needed by update and is maintained by the heap.Interface methods.
	index int // The index of the item in the heap.
}

func (t *ExecTask) ToRPC() *rpctype.ExecTask {
	return &rpctype.ExecTask{
		Prog: t.Program.Serialize(),
		ID:   t.ID,
	}
}

type ExecTaskFactory struct {
	chanMapMutex           sync.Mutex
	taskIDToExecResultChan map[int64]ExecResultChan
	taskCounter            int64
}

func MakeExecTaskFactory() *ExecTaskFactory {
	return &ExecTaskFactory{
		taskIDToExecResultChan: make(map[int64]ExecResultChan),
		taskCounter:            -1,
	}
}

type ExecResultChan chan *ExecResult

func (factory *ExecTaskFactory) MakeExecTask(prog *prog.Prog) *ExecTask {
	task := &ExecTask{
		CreationTime:   time.Now(),
		Program:        prog,
		ExecResultChan: make(ExecResultChan),
		ID:             atomic.AddInt64(&factory.taskCounter, 1),
	}

	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	factory.taskIDToExecResultChan[task.ID] = task.ExecResultChan

	return task
}

func (factory *ExecTaskFactory) ExecTasksQueued() int {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	return len(factory.taskIDToExecResultChan)
}

func (factory *ExecTaskFactory) DeleteExecTask(task *ExecTask) {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()
	delete(factory.taskIDToExecResultChan, task.ID)
}

func (factory *ExecTaskFactory) GetExecResultChan(taskID int64) ExecResultChan {
	factory.chanMapMutex.Lock()
	defer factory.chanMapMutex.Unlock()

	return factory.taskIDToExecResultChan[taskID]
}

func MakeExecTaskQueue() *ExecTaskQueue {
	return &ExecTaskQueue{
		pq: make(ExecTaskPriorityQueue, 0),
	}
}

// ExecTaskQueue respects the pq.priority. Internally it is a thread-safe PQ.
type ExecTaskQueue struct {
	pq ExecTaskPriorityQueue
	mu sync.Mutex
}

// PopTask return false if no tasks are available.
func (q *ExecTaskQueue) PopTask() (*ExecTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pq.Len() == 0 {
		return nil, false
	}
	return heap.Pop(&q.pq).(*ExecTask), true
}

func (q *ExecTaskQueue) PushTask(task *ExecTask) {
	q.mu.Lock()
	defer q.mu.Unlock()
	heap.Push(&q.pq, task)
}

func (q *ExecTaskQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pq.Len()
}

// ExecTaskPriorityQueue reused example from https://pkg.go.dev/container/heap
type ExecTaskPriorityQueue []*ExecTask

func (pq ExecTaskPriorityQueue) Len() int { return len(pq) }

func (pq ExecTaskPriorityQueue) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest, priority so we use greater than here.
	return pq[i].priority > pq[j].priority
}

func (pq ExecTaskPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *ExecTaskPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*ExecTask)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *ExecTaskPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}
