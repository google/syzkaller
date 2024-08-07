// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dispatcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPoolDefault(t *testing.T) {
	count := 3
	pool := makePool(count)

	mgr := NewPool[*testInstance](
		count,
		func(idx int) (*testInstance, error) {
			pool[idx].reset()
			return &pool[idx], nil
		},
		func(ctx context.Context, inst *testInstance, _ UpdateInfo) {
			pool[inst.Index()].run(ctx)
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		mgr.Loop(ctx)
		close(done)
	}()

	// Eventually all instances are up and busy.
	for i := 0; i < count; i++ {
		pool[i].waitRun()
	}

	// The pool restarts failed jobs.
	for i := 0; i < 10; i++ {
		pool[0].stopRun()
		pool[2].stopRun()

		pool[0].waitRun()
		pool[2].waitRun()
	}

	cancel()
	<-done
}

func TestPoolSplit(t *testing.T) {
	count := 3
	pool := makePool(count)
	var defaultCount atomic.Int64

	mgr := NewPool[*testInstance](
		count,
		func(idx int) (*testInstance, error) {
			pool[idx].reset()
			return &pool[idx], nil
		},
		func(ctx context.Context, inst *testInstance, _ UpdateInfo) {
			defaultCount.Add(1)
			pool[inst.Index()].run(ctx)
			defaultCount.Add(-1)
		},
	)

	done := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		mgr.Loop(ctx)
		close(done)
	}()

	startedRuns := make(chan bool)
	stopRuns := make(chan bool)
	job := func(ctx context.Context, _ *testInstance, _ UpdateInfo) {
		startedRuns <- true
		select {
		case <-ctx.Done():
		case <-stopRuns:
		}
	}
	go mgr.Run(job)

	// So far, there are no reserved instances.
	for i := 0; i < count; i++ {
		pool[i].waitRun()
	}

	// Dedicate one instance to the pool.
	mgr.ReserveForRun(1)

	// The first job must start.
	<-startedRuns
	// Two default jobs are running.
	assert.EqualValues(t, 2, defaultCount.Load())
	stopRuns <- true

	// Take away the pool instance.
	mgr.ReserveForRun(0)
	// All instances must be busy with the default jobs.
	for i := 0; i < count; i++ {
		pool[i].waitRun()
	}
	assert.EqualValues(t, 3, defaultCount.Load())

	// Now let's create and finish more jobs.
	for i := 0; i < 10; i++ {
		go mgr.Run(job)
	}
	mgr.ReserveForRun(2)
	for i := 0; i < 10; i++ {
		<-startedRuns
		stopRuns <- true
	}

	cancel()
	<-done
}

func TestPoolStress(t *testing.T) {
	// The test to aid the race detector.
	mgr := NewPool[*nilInstance](
		10,
		func(idx int) (*nilInstance, error) {
			return &nilInstance{}, nil
		},
		func(ctx context.Context, _ *nilInstance, _ UpdateInfo) {
			<-ctx.Done()
		},
	)
	done := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		mgr.Loop(ctx)
		close(done)
	}()
	for i := 0; i < 128; i++ {
		go mgr.Run(func(ctx context.Context, _ *nilInstance, _ UpdateInfo) {
		})
		mgr.ReserveForRun(5 + i%5)
	}

	cancel()
	<-done
}

func TestPoolNewDefault(t *testing.T) {
	var originalCount atomic.Int64

	// The test to aid the race detector.
	mgr := NewPool[*nilInstance](
		10,
		func(idx int) (*nilInstance, error) {
			return &nilInstance{}, nil
		},
		func(ctx context.Context, _ *nilInstance, _ UpdateInfo) {
			originalCount.Add(1)
			<-ctx.Done()
			originalCount.Add(-1)
		},
	)
	done := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		mgr.Loop(ctx)
		close(done)
	}()

	for originalCount.Load() != 10 {
		time.Sleep(time.Second / 10)
	}

	var newCount atomic.Int64
	mgr.SetDefault(func(ctx context.Context, _ *nilInstance, _ UpdateInfo) {
		newCount.Add(1)
		<-ctx.Done()
		newCount.Add(-1)
	})

	for newCount.Load() != 10 {
		time.Sleep(time.Second / 10)
	}
	assert.Equal(t, int64(0), originalCount.Load())

	cancel()
	<-done
}

func makePool(count int) []testInstance {
	var ret []testInstance
	for i := 0; i < count; i++ {
		ret = append(ret, testInstance{index: i})
	}
	return ret
}

type testInstance struct {
	index  int
	hasRun atomic.Bool
	stop   chan bool
}

func (ti *testInstance) reset() {
	ti.stop = make(chan bool)
	ti.hasRun.Store(false)
}

func (ti *testInstance) run(ctx context.Context) {
	ti.hasRun.Store(true)
	select {
	case <-ti.stop:
	case <-ctx.Done():
	}
}

func (ti *testInstance) waitRun() {
	for !ti.hasRun.Load() {
		time.Sleep(10 * time.Millisecond)
	}
}

func (ti *testInstance) stopRun() {
	close(ti.stop)
	ti.hasRun.Store(false) // make subsequent waitRun() actually wait for the next command.
}

func (ti *testInstance) Index() int {
	return ti.index
}

func (ti *testInstance) Close() error {
	return nil
}

type nilInstance struct {
}

func (ni *nilInstance) Close() error {
	return nil
}
