// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import "sync"

type Number interface {
	int | int64 | float64
}

type RunningAverage[T Number] struct {
	window []T
	mu     sync.RWMutex
	pos    int
	total  T
}

func NewRunningAverage[T Number](size int) *RunningAverage[T] {
	return &RunningAverage[T]{
		window: make([]T, size),
	}
}

func (ra *RunningAverage[T]) SaveInt(val int) {
	ra.Save(T(val))
}

func (ra *RunningAverage[T]) Save(val T) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	prev := ra.window[ra.pos]
	ra.window[ra.pos] = val
	ra.total += val - prev
	ra.pos = (ra.pos + 1) % len(ra.window)
}

func (ra *RunningAverage[T]) Load() T {
	ra.mu.RLock()
	defer ra.mu.RUnlock()
	return ra.total
}

type RunningRatioAverage[T Number] struct {
	values   *RunningAverage[T]
	divideBy *RunningAverage[T]
}

func NewRunningRatioAverage[T Number](size int) *RunningRatioAverage[T] {
	return &RunningRatioAverage[T]{
		values:   NewRunningAverage[T](size),
		divideBy: NewRunningAverage[T](size),
	}
}

func (rra *RunningRatioAverage[T]) Save(nomDelta, denomDelta T) {
	rra.values.Save(nomDelta)
	rra.divideBy.Save(denomDelta)
}

func (rra *RunningRatioAverage[T]) Load() float64 {
	denom := rra.divideBy.Load()
	if denom == 0 {
		return 0
	}
	return float64(rra.values.Load()) / float64(denom)
}
