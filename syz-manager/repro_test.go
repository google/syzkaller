// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/assert"
)

func TestReproManager(t *testing.T) {
	mock := &reproMgrMock{
		run: make(chan runCallback),
	}
	obj := newReproManager(mock, 3, false)

	ctx, done := context.WithCancel(context.Background())
	complete := make(chan struct{})
	go func() {
		obj.Loop(ctx)
		close(complete)
	}()

	defer func() {
		done()
		<-complete
	}()

	// No reproductions until we've signaled to start.
	assert.False(t, obj.CanReproMore())
	obj.StartReproduction()

	// No reproducers -- we can definitely take more.
	assert.True(t, obj.CanReproMore())
	obj.Enqueue(&Crash{Report: &report.Report{Title: "A"}})
	called := <-mock.run
	assert.Equal(t, "A", called.crash.Title)

	// One reproducer is running -- we can take one more.
	assert.True(t, obj.CanReproMore())
	assert.EqualValues(t, 2, mock.reserved.Load())
	obj.Enqueue(&Crash{Report: &report.Report{Title: "B"}})
	called2 := <-mock.run
	assert.Equal(t, "B", called2.crash.Title)

	assert.False(t, obj.CanReproMore())
	assert.Len(t, obj.Reproducing(), 2)
	assert.EqualValues(t, 3, mock.reserved.Load())

	// Pretend that reproducers have finished.
	called.ret <- &ReproResult{crash: &Crash{fromHub: true}}
	called2.ret <- &ReproResult{crash: &Crash{fromHub: true}}

	mock.onVMShutdown(t, obj)
}

func TestReproOrder(t *testing.T) {
	mock := &reproMgrMock{
		run: make(chan runCallback),
	}
	obj := newReproManager(mock, 3, false)

	// The right order is A B C.
	crashes := []*Crash{
		{
			Report:        &report.Report{Title: "A"},
			fromDashboard: true,
			manual:        true,
		},
		{
			Report:        &report.Report{Title: "B"},
			fromDashboard: true,
		},
		{
			Report:  &report.Report{Title: "C"},
			fromHub: true,
		},
	}

	obj.Enqueue(crashes[2])
	obj.Enqueue(crashes[1])
	obj.Enqueue(crashes[0])
	assert.Equal(t, crashes[0], obj.popCrash())
	assert.Equal(t, crashes[1], obj.popCrash())
	assert.Equal(t, crashes[2], obj.popCrash())

	obj.Enqueue(crashes[1])
	obj.Enqueue(crashes[0])
	obj.Enqueue(crashes[2])
	assert.Equal(t, crashes[0], obj.popCrash())
	assert.Equal(t, crashes[1], obj.popCrash())
	assert.Equal(t, crashes[2], obj.popCrash())
}

func TestReproRWRace(t *testing.T) {
	mock := &reproMgrMock{
		run: make(chan runCallback),
	}
	obj := newReproManager(mock, 3, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		obj.Loop(ctx) // calls runRepro()
	}()

	assert.False(t, obj.CanReproMore())
	obj.StartReproduction()
	assert.True(t, obj.CanReproMore())

	obj.Enqueue(&Crash{Report: &report.Report{Title: "A"}})
	obj.Enqueue(&Crash{Report: &report.Report{Title: "A"}})

	assert.True(t, mock.needRepro(nil))
	called := <-mock.run
	called.ret <- &ReproResult{}
	// Pretend that processRepro() is finished and
	// we've written "repro.prog" to the disk.
	mock.reproProgExist.Store(true)
	assert.False(t, mock.needRepro(nil))
	assert.True(t, obj.CanReproMore())

	called2 := <-mock.run
	called2.ret <- &ReproResult{}
	assert.False(t, mock.needRepro(nil))
	assert.True(t, obj.CanReproMore())

	// Reproducers may be still running.
	mock.onVMShutdown(t, obj)
}

type reproMgrMock struct {
	reserved       atomic.Int64
	run            chan runCallback
	reproProgExist atomic.Bool
}

type runCallback struct {
	crash *Crash
	ret   chan *ReproResult
}

// Wait until the number of reserved VMs goes to 0.
func (m *reproMgrMock) onVMShutdown(t *testing.T, reproMgr *reproManager) {
	for i := 0; i < 100; i++ {
		if m.reserved.Load() == 0 {
			assert.True(t, reproMgr.CanReproMore())
			assert.True(t, reproMgr.Empty())
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reserved VMs must have dropped to 0")
}

func (m *reproMgrMock) runRepro(crash *Crash) *ReproResult {
	retCh := make(chan *ReproResult)
	m.run <- runCallback{crash: crash, ret: retCh}
	ret := <-retCh
	close(retCh)
	return ret
}

func (m *reproMgrMock) needRepro(crash *Crash) bool {
	return !m.reproProgExist.Load()
}

func (m *reproMgrMock) resizeReproPool(VMs int) {
	m.reserved.Store(int64(VMs))
}
