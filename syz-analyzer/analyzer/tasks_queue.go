package main

import "fmt"

type TasksQueue struct {
	queue map[int][]int
}

func (tq *TasksQueue) push(vmID int, taskID int) {
	if tq.queue[vmID] == nil {
		tq.queue[vmID] = make([]int, 0)
	}

	tq.queue[vmID] = append(tq.queue[vmID], taskID)
}

func (tq *TasksQueue) getAndPop(vmID int) (int, error) {
	if tq.queue[vmID] == nil || len(tq.queue[vmID]) == 0 {
		err := fmt.Errorf("tasks qeue of vm %d is empty", vmID)
		return -1, err
	}
	taskID := tq.queue[vmID][0]
	tq.queue[vmID] = tq.queue[vmID][1:]

	return taskID, nil
}

func (tq *TasksQueue) isEmpty(vmID int) bool {
	if tq.queue[vmID] == nil || len(tq.queue[vmID]) == 0 {
		return true
	}
	return len(tq.queue[vmID]) == 0
}
