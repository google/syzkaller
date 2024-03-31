// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestReproLoopNoRepro(t *testing.T) {
	mgr := new(loopMgrMock)
	repros := newReproLoop(context.Background(), 5, mgr)

	// Scenario: dashapi says we don't need the reproducer.
	mgr.On("needRepro", mock.Anything).Return(false)

	repros.Process(&Crash{Report: &report.Report{Title: "A"}}, func(_ ...int) {})

	assert.Equal(t, uint32(0), repros.NumReproducing.Load())
	assert.Equal(t, uint32(0), repros.NumPending.Load())
	mgr.AssertExpectations(t)
}

func TestReproLoopRepro(t *testing.T) {
	mgr := new(loopMgrMock)
	repros := newReproLoop(context.Background(), 3, mgr)

	mgr.On("needRepro", mock.Anything).Return(true).Once()
	crash := &Crash{Report: &report.Report{Title: "A"}}
	result := &ReproResult{
		report0: crash.Report,
		repro:   &repro.Result{Report: &report.Report{Title: "B"}},
	}
	mgr.On("runRepro", crash, []int{0, 1, 2}, mock.Anything).Once().Return(result)
	mgr.On("saveRepro", result).Once()

	done := make(chan struct{})
	go func() {
		repros.Process(crash, func(_ ...int) {})
		done <- struct{}{}
	}()

	takeInstanceWait(t, repros, 0)
	assert.Equal(t, uint32(1), repros.NumPending.Load())
	assert.True(t, repros.TakeInstance(1))
	assert.True(t, repros.TakeInstance(2))

	<-done
	assert.Equal(t, uint32(0), repros.NumPending.Load())
	mgr.AssertExpectations(t)
}

func TestReproLoopFailed(t *testing.T) {
	mgr := new(loopMgrMock)
	repros := newReproLoop(context.Background(), 3, mgr)

	crash := &Crash{Report: &report.Report{Title: "A"}}
	mgr.On("needRepro", crash).Return(true).Once()
	result := &ReproResult{
		report0: crash.Report,
		stats:   &repro.Stats{},
	}
	mgr.On("runRepro", crash, []int{0, 1, 2}, mock.Anything).Once().Return(result)
	mgr.On("saveFailedRepro", crash.Report, result.stats).Once()

	done := make(chan struct{})
	go func() {
		repros.Process(crash, func(_ ...int) {})
		done <- struct{}{}
	}()

	takeInstanceWait(t, repros, 0)
	assert.True(t, repros.TakeInstance(1))
	assert.True(t, repros.TakeInstance(2))

	<-done
	mgr.AssertExpectations(t)
}

func TestReproLoopHubFailed(t *testing.T) {
	mgr := new(loopMgrMock)
	repros := newReproLoop(context.Background(), 3, mgr)

	crash := &Crash{Report: &report.Report{Title: "A"}, fromHub: true}
	mgr.On("needRepro", crash).Return(true).Once()
	result := &ReproResult{
		report0: crash.Report,
		stats:   &repro.Stats{},
		fromHub: true,
	}
	mgr.On("runRepro", crash, []int{0, 1}, mock.Anything).Once().Return(result)

	done := make(chan struct{})
	go func() {
		repros.Process(crash, func(_ ...int) {})
		done <- struct{}{}
	}()

	takeInstanceWait(t, repros, 0)
	assert.True(t, repros.TakeInstance(1))
	assert.False(t, repros.TakeInstance(2))
	assert.False(t, repros.WantVMs())

	<-done
	mgr.AssertExpectations(t)
}

func TestReproLoopContention(t *testing.T) {
	mgr := new(loopMgrMock)
	mgr.On("needRepro", mock.Anything).Return(true).Times(3)
	repros := newReproLoop(context.Background(), 7, mgr)
	putInstances := func(idx ...int) {}

	// We don't care about the specific value.
	result := &ReproResult{report0: &report.Report{Title: "X"}, stats: &repro.Stats{}}

	// First crash.
	crash1 := &Crash{Report: &report.Report{Title: "A"}}
	first := make(chan struct{})
	mgr.On("runRepro", crash1, []int{0, 1, 2}, mock.Anything).Run(func(_ mock.Arguments) {
		first <- struct{}{}
		<-first
	}).Return(result)
	mgr.On("saveFailedRepro", mock.Anything, mock.Anything).Times(3)

	done := make(chan struct{})
	go func() {
		repros.Process(crash1, putInstances)
		done <- struct{}{}
	}()
	takeInstanceWait(t, repros, 0)
	assert.True(t, repros.TakeInstance(1))
	assert.True(t, repros.TakeInstance(2))
	<-first
	assert.Equal(t, uint32(1), repros.NumReproducing.Load())

	// Second crash.
	second := make(chan struct{})
	crash2 := &Crash{Report: &report.Report{Title: "B"}}
	mgr.On("runRepro", crash2, []int{3, 4, 5}, mock.Anything).Run(func(_ mock.Arguments) {
		second <- struct{}{}
		<-second
	}).Return(result)

	go func() {
		repros.Process(crash2, putInstances)
		done <- struct{}{}
	}()
	takeInstanceWait(t, repros, 3)
	assert.True(t, repros.TakeInstance(4))
	assert.True(t, repros.TakeInstance(5))
	<-second
	assert.Equal(t, uint32(2), repros.NumReproducing.Load())

	// Third crash.
	crash3 := &Crash{Report: &report.Report{Title: "C"}}
	mgr.On("runRepro", crash3, []int{6, 0, 1}, mock.Anything).Return(result)

	go func() {
		repros.Process(crash3, putInstances)
		done <- struct{}{}
	}()

	// There's capacity and need for one more VM, but not more.
	takeInstanceWait(t, repros, 6)
	assert.False(t, repros.TakeInstance(0))
	assert.False(t, repros.WantVMs())
	assert.Equal(t, map[string]bool{
		"A": true,
		"B": true,
		"C": true,
	}, repros.Reproducing())

	// Now let's finish the first reproduction.
	// It should leave space for the third.
	first <- struct{}{}
	<-done
	takeInstanceWait(t, repros, 0)
	takeInstanceWait(t, repros, 1)

	second <- struct{}{}
	<-done
	<-done

	assert.Equal(t, uint32(0), repros.NumReproducing.Load())
	assert.Equal(t, map[string]bool{}, repros.Reproducing())
	mgr.AssertExpectations(t)
}

// Wait until it is ready to accept the first instance.
func takeInstanceWait(t *testing.T, repros *reproLoop, idx int) {
	for i := 0; i <= 100; i++ {
		time.Sleep(time.Millisecond)
		if repros.TakeInstance(idx) {
			break
		}
		assert.True(t, i < 100)
	}
}

type loopMgrMock struct {
	mock.Mock
}

func (lm *loopMgrMock) runRepro(crash *Crash, vmIndices []int, putInstances func(...int)) *ReproResult {
	args := lm.Called(crash, vmIndices, putInstances)
	for _, id := range vmIndices {
		putInstances(id)
	}
	return args.Get(0).(*ReproResult)
}

func (lm *loopMgrMock) needRepro(crash *Crash) bool {
	args := lm.Called(crash)
	return args.Bool(0)
}

func (lm *loopMgrMock) saveRepro(res *ReproResult) {
	lm.Called(res)
}

func (lm *loopMgrMock) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	lm.Called(rep, stats)
}
