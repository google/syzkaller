// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
)

// Time unit is important since MAB ended up converting coverage
// gained into time, before feeding it to the exponential growth
// algorithm. Converting time unit from ns to s can prevent overflow
// of float64 when computing exponentials
const (
	MABTimeUnit = 1000000000.0
	MABLogLevel = 4
)

type MABStatus struct {
	fuzzer *Fuzzer

	MABMu     sync.RWMutex
	SSEnabled bool
	TSEnabled bool

	SSGamma float64
	SSEta   float64
	TSGamma float64
	TSEta   float64

	Round          int         // How many MAB choices have been made
	Exp31Round     int         // Round # for Exp3.1.
	Exp31Threshold float64     // Threshold based on Round.
	CorpusUpdate   map[int]int // Track seed priority update
	Reward         mab.TotalReward
}

func (status *MABStatus) GetTSWeight(lock bool) []float64 {
	if lock {
		status.MABMu.Lock()
		defer status.MABMu.Unlock()
	}
	x := []float64{0.0, 0.0, 0.0}
	weight := []float64{1.0, 1.0, 1.0}
	eta := status.TSEta
	const (
		MABWeightThresholdMax = 1.0e+300
		MABWeightThresholdMin = 1.0e-300
	)
	x[0] = eta * status.Reward.EstimatedRewardGenerate
	x[1] = eta * status.Reward.EstimatedRewardMutate
	x[2] = eta * status.Reward.EstimatedRewardTriage
	log.Logf(MABLogLevel, "MABWeight %v\n", x)
	// Compute median to prevent overflow
	median := x[0]
	if x[0] > x[1] {
		if x[1] > x[2] {
			median = x[1]
		} else if x[0] > x[2] {
			median = x[2]
		}
	} else {
		if x[1] < x[2] {
			median = x[1]
		} else if x[0] < x[2] {
			median = x[2]
		}
	}
	for i := 0; i <= 2; i++ {
		weight[i] = math.Exp(x[i] - median)
		if weight[i] > MABWeightThresholdMax {
			weight[i] = MABWeightThresholdMax
		}
		if weight[i] < MABWeightThresholdMin {
			weight[i] = MABWeightThresholdMin
		}
	}
	return weight
}
