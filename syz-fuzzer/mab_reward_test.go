// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/mab"
)

func initTestMabStatus(rawCov, rawTime, totalReward []float64) MABStatus {
	status := MABStatus{
		TSEnabled:      true,
		SSEnabled:      true,
		CorpusUpdate:   make(map[int]int),
		TSGamma:        0.05,
		TSEta:          0.1,
		SSGamma:        0.05,
		SSEta:          0.1,
		Round:          0,
		Exp31Round:     1,
		Exp31Threshold: 1.0,
		Reward:         mab.TotalReward{},
	}
	status.Reward.RawAllTasks.Update(rawCov, rawTime)
	status.Reward.RewardAllTasks.Update(totalReward, 0.0)
	return status
}

func TestRewardComputation(t *testing.T) {
	status := initTestMabStatus([]float64{2.0, 4.0, 6.0}, []float64{0.2, 0.4, 0.6}, []float64{2.0, 4.0, 6.0})
	reward := status.ComputeTSReward(1.0, 1.0)
}
