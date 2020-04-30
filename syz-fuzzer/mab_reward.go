// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
)

func ComputeReward(cov float64, time float64, totalReward *mab.Reward) float64 {
	if totalReward.TotalCov > 0 {
		ret := cov*(totalReward.TotalTime/totalReward.TotalCov) - time
		log.Logf(MABLogLevel, "MAB Reward: %v * %v / %v - %v = %v",
			cov, totalReward.TotalTime,
			totalReward.TotalCov, time,
			ret)
		return ret
	}
	return 0.0
}

func (status *MABStatus) ComputeTSReward(cov float64, time float64) float64 {
	return ComputeReward(cov, time, &status.Reward.RawAllTasks)
}

func (status *MABStatus) ComputeSSReward(cov float64, time float64) float64 {
	return ComputeReward(cov, time, &status.Reward.RawMutateOnly)
}

func NormalizeReward(reward float64, totalReward *mab.Reward) float64 {
	// Use Z-score + logistic function to normalize reward to [-1,1]
	// If there is an error, return 0.0
	if totalReward.Count == 0 {
		return 0.0
	}
	// First standardize reward using Z-score shifted to a mean of 0
	meanX := totalReward.TotalCov / float64(totalReward.Count)
	stdX := (totalReward.TotalCov2 / float64(totalReward.Count)) - (meanX * meanX)
	if stdX < 0.0 {
		log.Logf(MABLogLevel, "Error: Cannot compute std sqrt(%v)", stdX)
		return 0.0
	} else if stdX == 0.0 {
		return 0.0
	}
	stdX = math.Sqrt(stdX)
	// Normally, Z-score should be z = (reward - meanX) / stdX.
	// However, we want to make sure positive reward is positive.
	// In later stages of fuzzing, meanX is going to be negative.
	// We don't want an "arm" with negative reward be rewarded
	z := reward / stdX
	// Prevent overflowing
	if z > 16.0 {
		return 1
	} else if z < -16.0 {
		return -1
	}
	// Next, logistic function scaled to [-1, 1]
	x := (1.0 - math.Exp(-z)) / (1.0 + math.Exp(-z))
	log.Logf(MABLogLevel, "MAB Normalized Reward: %v; z=%v mean=%v std=%v", x, z, meanX, stdX)
	return x
}

func (status *MABStatus) NormalizeTSReward(reward float64) float64 {
	return NormalizeReward(reward, &status.Reward.RewardAllTasks)
}

func (status *MABStatus) NormalizeSSReward(reward float64) float64 {
	return NormalizeReward(reward, &status.Reward.RewardMutateOnly)
}

// Estimate reward computation, according to Exp3-IX
func EstimateReward(reward, pr, gamma float64) float64 {
	ret := reward / (pr + gamma)
	log.Logf(MABLogLevel, "MAB Estimate Reward: %v / (%v + %v) = %v\n",
		reward, pr, gamma, ret)
	return ret
}

func (status *MABStatus) EstimateTSReward(reward, pr float64) float64 {
	return EstimateReward(reward, pr, status.TSGamma)
}

func (status *MABStatus) EstimateSSReward(reward, pr float64) float64 {
	return EstimateReward(reward, pr, status.SSGamma)
}
