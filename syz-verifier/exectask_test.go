// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
)

func TestExecTask_MakeDelete(t *testing.T) {
	program := getTestProgram(t)
	taskFactory := MakeExecTaskFactory()
	if l := taskFactory.ExecTasksQueued(); l != 0 {
		t.Errorf("expected to see empty map, current size is %v", l)
	}
	task := taskFactory.MakeExecTask(program)
	if l := taskFactory.ExecTasksQueued(); l != 1 {
		t.Errorf("expected map len is 0, current size is %v", l)
	}
	taskFactory.DeleteExecTask(task)
	if l := taskFactory.ExecTasksQueued(); l != 0 {
		t.Errorf("expected map len is 0, current size is %v", l)
	}
}

func TestExecTask_ToRPC(t *testing.T) {
	program := getTestProgram(t)
	taskFactory := MakeExecTaskFactory()
	task := taskFactory.MakeExecTask(program)
	if task.ToRPC() == nil {
		t.Errorf("rpcView generation failed")
	}
}

func TestGetExecResultChan(t *testing.T) {
	taskFactory := MakeExecTaskFactory()
	if l := taskFactory.ExecTasksQueued(); l != 0 {
		t.Errorf("expected to see empty map, current size is %v", l)
	}
	ch := taskFactory.GetExecResultChan(100)
	if l := taskFactory.ExecTasksQueued(); l != 0 {
		t.Errorf("expected to see empty map, current size is %v", l)
	}
	if ch != nil {
		t.Errorf("expected to see nil channel")
	}
}

func TestExecTaskQueue_PushTask(t *testing.T) {
	q := MakeExecTaskQueue()
	if l := q.Len(); l != 0 {
		t.Errorf("expected to see zero len, current is %v", l)
	}

	taskFactory := MakeExecTaskFactory()
	q.PushTask(taskFactory.MakeExecTask(getTestProgram(t)))
	if l := q.Len(); l != 1 {
		t.Errorf("expected to see single element, current size is %v", l)
	}
}

func TestExecTaskQueue_PopTask(t *testing.T) {
	q := MakeExecTaskQueue()
	task, gotResult := q.PopTask()
	if task != nil || gotResult != false {
		t.Errorf("empty queue operation error")
	}
	program := getTestProgram(t)
	taskFactory := MakeExecTaskFactory()
	q.PushTask(taskFactory.MakeExecTask(program))
	q.PushTask(taskFactory.MakeExecTask(program))
	q.PushTask(taskFactory.MakeExecTask(program))
	task, gotResult = q.PopTask()
	if task == nil || gotResult == false {
		t.Errorf("non-empty task or error was expected")
	}
}
