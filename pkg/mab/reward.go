// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mab

type Reward struct {
	Count      int
	TotalCov   float64 // sum(cov)
	TotalTime  float64 // sum(time)
	TotalCov2  float64 // sum(cov * cov). Used to compute std
	TotalTime2 float64 // sum(time * time). Used to compute std
}

type TotalReward struct {
	// For Task Scheduling
	EstimatedRewardGenerate float64 // Estimated reward for Generate. Used for weight deciding
	EstimatedRewardMutate   float64 // Estimated reward for Mutate. Used for weight deciding
	EstimatedRewardTriage   float64 // Estimated reward for Triage. Used for weight deciding
	RawAllTasks             Reward  // Raw cov/time for all Gen/Mut/Tri. Used for computing expected time
	RewardAllTasks          Reward  // Cov/time converted to reward for all Gen/Mut/Tri. Used for normalization

	// For Seed selection
	RawMutateOnly    Reward // Raw cov/time for mutations. Used for Nael's computation for seed selection
	RewardMutateOnly Reward // Cov/time converted to reward for mutations only. Used for normalization
}

// Reward and time time information for each seed
type CorpusReward struct {
	MutateCount      int     // Number of times this seed has been mutated
	ExecTime         float64 // Execution time
	MutateTime       float64 // Total time of mutating this seed
	MutateCov        float64 // Total coverage cov of mutating this seed
	VerifyTime       float64 // Time time of verifing this seed
	MinimizeCov      float64 // Coverage coved from minimization
	MinimizeTime     float64 // Time time of minimization
	MinimizeTimeSave float64 // Estimated time save due to minimization
	MutateReward     float64 // Converted reward of mutating this seed. Coversion based on all tasks
	MutateRewardOrig float64 // Converted reward of mutating this seed. Conversion based on mutations only
	TriageReward     float64 // Converted reward of triaging this seed
}

func (reward *Reward) Update(cov float64, time float64) {
	const Max = 1.0e+100 // Prevent overflow

	reward.Count++
	reward.TotalCov += cov
	reward.TotalCov2 += cov * cov
	reward.TotalTime += time
	reward.TotalTime2 += time * time
	if reward.TotalCov > Max {
		reward.TotalCov = Max
	}
	if reward.TotalCov2 > Max {
		reward.TotalCov2 = Max
	}
	if reward.TotalTime > Max {
		reward.TotalTime = Max
	}
	if reward.TotalTime2 > Max {
		reward.TotalTime2 = Max
	}
}

func (reward *Reward) Remove(cov float64, time float64) {
	reward.Count--
	reward.TotalCov -= cov
	reward.TotalCov2 -= cov * cov
	reward.TotalTime -= time
	reward.TotalTime2 -= time * time
}
