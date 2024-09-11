// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

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
	obj := NewReproLoop(mock, 3, false)
	// No reproductions until we've started.
	assert.False(t, obj.CanReproMore())

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
	called.ret <- &ReproResult{Crash: &Crash{FromHub: true}}
	called2.ret <- &ReproResult{Crash: &Crash{FromHub: true}}

	mock.onVMShutdown(t, obj)
}

func TestReproOrder(t *testing.T) {
	mock := &reproMgrMock{
		run: make(chan runCallback),
	}
	obj := NewReproLoop(mock, 1, false)

	// The right order is A B C.
	crashes := []*Crash{
		{
			Report:        &report.Report{Title: "A"},
			FromDashboard: true,
			Manual:        true,
		},
		{
			Report:        &report.Report{Title: "B"},
			FromDashboard: true,
		},
		{
			Report:  &report.Report{Title: "C"},
			FromHub: true,
		},
	}

	obj.Enqueue(crashes[2])
	obj.Enqueue(crashes[1])
	obj.Enqueue(crashes[0])
	obj.Enqueue(crashes[1])
	obj.Enqueue(crashes[0])
	obj.Enqueue(crashes[2])

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go obj.Loop(ctx)

	for i := 0; i < len(crashes)*2; i++ {
		called := <-mock.run
		assert.Equal(t, crashes[i%len(crashes)], called.crash)
		called.ret <- &ReproResult{}
	}
}

func TestReproRWRace(t *testing.T) {
	mock := &reproMgrMock{
		run: make(chan runCallback),
	}
	obj := NewReproLoop(mock, 3, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go obj.Loop(ctx) // calls runRepro()

	obj.Enqueue(&Crash{Report: &report.Report{Title: "A"}})
	obj.Enqueue(&Crash{Report: &report.Report{Title: "A"}})

	assert.True(t, mock.NeedRepro(nil))
	called := <-mock.run
	// Pretend that processRepro() is finished and
	// we've written "repro.prog" to the disk.
	mock.reproProgExist.Store(true)
	assert.False(t, mock.NeedRepro(nil))
	called.ret <- &ReproResult{}
	assert.True(t, obj.CanReproMore())

	// The second repro process will never be started.
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
func (m *reproMgrMock) onVMShutdown(t *testing.T, reproLoop *ReproLoop) {
	for i := 0; i < 100; i++ {
		if m.reserved.Load() == 0 {
			assert.True(t, reproLoop.CanReproMore())
			assert.True(t, reproLoop.Empty())
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reserved VMs must have dropped to 0")
}

func (m *reproMgrMock) RunRepro(crash *Crash) *ReproResult {
	retCh := make(chan *ReproResult)
	m.run <- runCallback{crash: crash, ret: retCh}
	ret := <-retCh
	close(retCh)
	return ret
}

func (m *reproMgrMock) NeedRepro(crash *Crash) bool {
	return !m.reproProgExist.Load()
}

func (m *reproMgrMock) ResizeReproPool(VMs int) {
	m.reserved.Store(int64(VMs))
}
