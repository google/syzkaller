// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math/rand"
	"sync"
)

type Action[T comparable] struct {
	Arm   T
	index int
}

func (a Action[T]) Empty() bool {
	return a == Action[T]{}
}

type countedValue struct {
	value float64
	count int64
}

func (cv *countedValue) update(value, minStep float64) {
	// Using larger steps at the beginning allows us to
	// converge faster to the actual value.
	// The minStep limit ensures that we can still track
	// non-stationary problems.
	cv.count++
	step := 1.0 / float64(cv.count)
	if step < minStep {
		step = minStep
	}
	cv.value += (value - cv.value) * step
}

// PlainMAB is a very simple epsylon-greedy MAB implementation.
type PlainMAB[T comparable] struct {
	MinLearningRate float64
	ExplorationRate float64

	mu      sync.RWMutex
	arms    []T
	weights []countedValue
}

func (p *PlainMAB[T]) AddArms(arms ...T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, arm := range arms {
		p.arms = append(p.arms, arm)
		p.weights = append(p.weights, countedValue{0, 0})
	}
}

func (p *PlainMAB[T]) Action(r *rand.Rand) Action[T] {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var pos int
	if r.Float64() < p.ExplorationRate {
		pos = r.Intn(len(p.arms))
	} else {
		for i := 1; i < len(p.arms); i++ {
			if p.weights[i].value > p.weights[pos].value {
				pos = i
			}
		}
	}
	return Action[T]{Arm: p.arms[pos], index: pos}
}

func (p *PlainMAB[T]) SaveReward(action Action[T], reward float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.weights[action.index].update(reward, p.MinLearningRate)
}
