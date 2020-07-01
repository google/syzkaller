// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math"
	"math/rand"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/log"
)

const MABLogLevel = 4

type Choice struct {
	reward     float64 // Normalized reward.
	weight     float64 // Weight proportional to reward. Subject to float64 overflow prevention.
	sumWeights float64 // Sum of weights up to current choice.
}

type MultiArmedBandit struct {
	Mu      sync.RWMutex
	Choices []Choice // Choices.

	Theta float64 // Factor controlling gamma and eta.
	Gamma float64 // Exploration factor.
	Eta   float64 // Growth factor.
}

// Randomly chooses an "arm" in the Choices array.
// Returns both the choice as well as the probability of making this choice.
func (mab *MultiArmedBandit) Choose(r *rand.Rand) (int, float64) {
	mab.Mu.RLock()
	defer mab.Mu.RUnlock()

	if len(mab.Choices) == 0 {
		return -1, 0.0
	}
	sumWeights := mab.Choices[len(mab.Choices)-1].sumWeights
	randVal := r.Float64() * mab.Choices[len(mab.Choices)-1].sumWeights
	idx := sort.Search(len(mab.Choices), func(i int) bool {
		return mab.Choices[i].sumWeights >= randVal
	})
	return idx, mab.Choices[idx].weight / sumWeights
}

func (mab *MultiArmedBandit) NewChoice() int {
	newChoice := Choice{
		reward:     0.0,
		weight:     1.0,
		sumWeights: 1.0,
	}
	if len(mab.Choices) > 0 {
		newChoice.sumWeights = mab.Choices[len(mab.Choices)-1].sumWeights + newChoice.weight
	}
	mab.Choices = append(mab.Choices, newChoice)
	// Need to update exploration and exploitation factors
	K := float64(len(mab.Choices))
	mab.Eta = mab.Theta * math.Sqrt(2.0*math.Log(K)/K)
	mab.Gamma = mab.Eta / 2.0
	log.Logf(MABLogLevel, "MAB Gamma = %v, Eta = %v", mab.Gamma, mab.Eta)

	return len(mab.Choices) - 1
}

func (mab *MultiArmedBandit) Update(idx int, reward, pr float64) {
	mab.Mu.RLock()
	defer mab.Mu.RUnlock()

	if idx >= len(mab.Choices) {
		log.Logf(MABLogLevel, "MAB Update Error: Index %v out of bound %v\n", idx, len(mab.Choices))
		return
	}
	if pr == 0 {
		log.Logf(MABLogLevel, "MAB Update Error: Probability is zero\n")
		return
	}
	// Reward should have been normalized to [-1, 1]
	if reward > 1.0 {
		reward = 1.0
	}
	if reward < -1.0 {
		reward = -1.0
	}
	// Update reward based on growth factor
	mab.Choices[idx].reward += mab.Eta * reward / (pr + mab.Gamma)
	// Update selection weight and prevent float64 overflow
	weightThresholdMax := math.Exp(16)
	weightThresholdMin := math.Exp(-16)
	weight := math.Exp(mab.Choices[idx].reward)
	if weight > weightThresholdMax {
		weight = weightThresholdMax
	}
	if weight < weightThresholdMin {
		weight = weightThresholdMin
	}
	mab.Choices[idx].weight = weight
	// Update sumWeights
	if idx == 0 {
		mab.Choices[idx].sumWeights = mab.Choices[idx].weight
	} else {
		mab.Choices[idx].sumWeights = mab.Choices[idx-1].sumWeights + mab.Choices[idx].weight
	}
	for i := idx + 1; i < len(mab.Choices); i++ {
		mab.Choices[i].sumWeights = mab.Choices[i-1].sumWeights + mab.Choices[i].weight
	}
}
