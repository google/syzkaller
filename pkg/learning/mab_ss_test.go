// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math"
	"math/rand"
	"testing"
)

// Tests Update() computes the correct normalized reward.
func TestMABSeedSchedulerUpdate(t *testing.T) {
	ss := NewMABSeedScheduler(0.1)
	const (
		numChoices = 6
		eps        = 0.001
	)
	for i := 0; i < numChoices; i++ {
		ss.NewChoice(nil)
	}
	// Parameters sent to ss.Update().
	rewards := [numChoices]ExecResult{
		{Coverage: 100, TimeExec: 0}, // Bad measurement won't get updated.
		{Coverage: 100, TimeExec: 1000000},
		{Coverage: 0, TimeExec: 1000000},
		{Coverage: 100, TimeExec: 10000000},
		{Coverage: 10, TimeExec: 1000000},
		{Coverage: 100, TimeExec: 1000000},
	}
	// Normalized rewards for each choice.
	normRewards := [numChoices]float64{
		0.0,     // rate=NaN, reward=0.0, std=0.0, z=NaN
		0.0,     // rate=NaN, reward=0.0, std=0.0, z=NaN
		0.0,     // rate=10000, reward=-1000000, std=0.0, z=NaN
		-1.0,    // rate=20000, reward=-8000000, std=500000, z=-16
		-0.0561, // rate=60000, reward=-400000, std=3559026, z=-0.1124
		0.6589,  // rate=61905, reward=5190500, std=3281387, z=1.5818
	}
	// Update.
	for c := 0; c < numChoices; c++ {
		ss.Update(c, rewards[c], 1.0)
	}
	// Check result.
	for c := 0; c < numChoices; c++ {
		expectedReward := ss.mab.eta * normRewards[c] / (1.0 + ss.mab.gamma)
		if math.Abs(ss.mab.choices[c].reward-expectedReward) > eps {
			t.Fatalf("incorrect reward (%v) for choice %v. expecting %v +- %v.",
				ss.mab.choices[c].reward, c, expectedReward, eps)
		}
	}
}

// Tests Choice() when MAB engine is empty.
func TestMABSeedEmptyChoice(t *testing.T) {
	ss := NewMABSeedScheduler(0.1)
	rs := rand.NewSource(0)
	r := rand.New(rs)
	idx, pr, corpus := ss.Choose(r)
	if idx >= 0 {
		t.Fatalf("incorrect index (%v). expecting < 0.", idx)
	}
	if pr != 0.0 {
		t.Fatalf("incorrect probability (%v). expecting 0.", pr)
	}
	if len(corpus) != 0 {
		t.Fatalf("incorrect corpus (length=%v). expecting empty.", len(corpus))
	}
}
