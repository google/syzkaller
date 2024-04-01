// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMABSmallDiff(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	bandit := &PlainMAB[int]{
		MinLearningRate: 0.0001,
		ExplorationRate: 0.1,
	}
	arms := []float64{0.65, 0.7}
	for i := range arms {
		bandit.AddArms(i)
	}
	const steps = 40000
	counts := runMAB(r, bandit, arms, steps)
	t.Logf("counts: %v", counts)
	assert.Greater(t, counts[1], steps/4*3)
}

func TestNonStationaryMAB(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	bandit := &PlainMAB[int]{
		MinLearningRate: 0.02,
		ExplorationRate: 0.04,
	}

	arms := []float64{0.2, 0.7, 0.5, 0.1}
	for i := range arms {
		bandit.AddArms(i)
	}

	const steps = 25000
	counts := runMAB(r, bandit, arms, steps)
	t.Logf("initially: %v", counts)

	// Ensure that we've found the best arm.
	assert.Greater(t, counts[1], steps/2)

	// Now change the best arm's avg reward.
	arms[3] = 0.9
	counts = runMAB(r, bandit, arms, steps)
	t.Logf("after reward change: %v", counts)
	assert.Greater(t, counts[3], steps/2)
}

func runMAB(r *rand.Rand, bandit *PlainMAB[int], arms []float64, steps int) []int {
	counts := make([]int, len(arms))
	for i := 0; i < steps; i++ {
		action := bandit.Action(r)
		// TODO: use normal distribution?
		reward := r.Float64() * arms[action.Arm]
		counts[action.Arm]++
		bandit.SaveReward(action, reward)
	}
	return counts
}
