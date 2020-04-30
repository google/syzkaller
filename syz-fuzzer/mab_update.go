// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
)

func PreprocessResult(result interface{}) interface{} {
	// Deal with cost outlier
	costMax := 1000000000.0 / MABTimeUnit

	switch result.(type) {
	case mab.ExecResult:
		{
			_r, ok := result.(mab.ExecResult)
			if ok {
				if _r.TimeExec > costMax {
					_r.TimeExec = costMax
				} else if _r.TimeExec < 0.0 {
					_r.TimeExec = 0.0
				}
			}
			return _r
		}
	case mab.TriageResult:
		{
			_r, ok := result.(mab.TriageResult)
			if ok {
				if _r.VerifyTime > costMax {
					_r.VerifyTime = costMax
				} else if _r.VerifyTime < 0.0 {
					_r.VerifyTime = 0.0
				}
				if _r.MinimizeTime > costMax {
					_r.MinimizeTime = costMax
				} else if _r.MinimizeTime < 0.0 {
					_r.MinimizeTime = 0.0
				}
				if _r.MinimizeTimeSave > costMax || _r.MinimizeTimeSave < -costMax {
					_r.MinimizeTimeSave = 0
				}
			}
			return _r
		}
	default:
		log.Fatalf("unknown result type: %#v", result)
	}
	return result
}

func (status *MABStatus) ResetTS() {
	// Reset only applies to task selection
	status.Reward.EstimatedRewardGenerate = 0.0
	status.Reward.EstimatedRewardMutate = 0.0
	status.Reward.EstimatedRewardTriage = 0.0
	status.Reward.RewardAllTasks = mab.Reward{}
}

func (status *MABStatus) BootstrapExp31() {
	status.TSGamma = math.Exp2(float64(-status.Exp31Round))
	status.TSEta = 2.0 * status.TSGamma
	status.Exp31Threshold = 3.0 * math.Log(3.0) * math.Exp2(2.0*float64(status.Exp31Round)) / (math.E - 1.0)
	status.Exp31Threshold = status.Exp31Threshold - (3.0 / status.TSGamma)
	log.Logf(MABLogLevel,
		"MAB Exp3.1 New Round %v, Gamma: %v, Eta: %v, Threshold: %v\n",
		status.Exp31Round, status.TSGamma, status.TSEta, status.Exp31Threshold)
}

func (status *MABStatus) UpdateSeedWeight(pidx int, reward float64) {
	// Update estimate reward
	status.fuzzer.corpus[pidx].CorpusReward.MutateRewardOrig += status.fuzzer.MABStatus.SSEta * reward
	// Update corpus selection weight
	weightThresholdMax := math.Exp(16)
	weightThresholdMin := math.Exp(-16)
	prio := 1.0
	prio = math.Exp(status.fuzzer.corpus[pidx].CorpusReward.MutateRewardOrig)
	if prio > weightThresholdMax {
		prio = weightThresholdMax
	}
	if prio < weightThresholdMin {
		prio = weightThresholdMin
	}
	log.Logf(MABLogLevel, "MAB Corpus %v, %v: %v -> %v",
		pidx, status.fuzzer.corpus[pidx].CorpusReward.MutateRewardOrig,
		status.fuzzer.corpusPrios[pidx], prio)
	status.fuzzer.corpusPrios[pidx] = prio
	if pidx == 0 {
		status.fuzzer.sumPrios[pidx] = status.fuzzer.corpusPrios[pidx]
	} else {
		status.fuzzer.sumPrios[pidx] = status.fuzzer.sumPrios[pidx-1] + status.fuzzer.corpusPrios[pidx]
	}
	for i := pidx + 1; i < len(status.fuzzer.corpus); i++ {
		status.fuzzer.sumPrios[i] = status.fuzzer.sumPrios[i-1] + status.fuzzer.corpusPrios[i]
	}
}

func (status *MABStatus) UpdateTriageWeight(result mab.TriageResult, pr []float64) {
	cov := float64(result.MinimizeCov)
	timeVerify := result.VerifyTime
	timeMinimize := result.MinimizeTime
	timeSave := result.MinimizeTimeSave
	pidx := result.Pidx
	// Convert and normalize
	reward := status.ComputeTSReward(cov, timeVerify+timeMinimize)
	rewardNorm := status.NormalizeTSReward(reward)
	rewardEst := status.EstimateTSReward(rewardNorm, pr[2])
	// Update
	status.Reward.EstimatedRewardTriage += rewardEst
	status.Reward.RewardAllTasks.Update(reward, 0.0)
	status.Reward.RawAllTasks.Update(cov, timeVerify+timeMinimize)
	// If triage succeed, record for SS
	if result.Success && pidx >= 0 && pidx < len(status.fuzzer.corpus) {
		status.fuzzer.corpus[pidx].CorpusReward.TriageReward = rewardNorm
		status.fuzzer.corpus[pidx].CorpusReward.MinimizeCov = float64(result.MinimizeCov)
		status.fuzzer.corpus[pidx].CorpusReward.VerifyTime = timeVerify
		status.fuzzer.corpus[pidx].CorpusReward.MinimizeTime = timeMinimize
		status.fuzzer.corpus[pidx].CorpusReward.MinimizeTimeSave = timeSave
		// Mark seed for update
		status.CorpusUpdate[pidx] = 1
	}
}

func (status *MABStatus) UpdateGenerateWeight(result mab.ExecResult, pr []float64) {
	cov := float64(result.Cov)
	time := result.TimeExec
	// Convert and normalize
	reward := status.ComputeTSReward(cov, time)
	rewardNorm := status.NormalizeTSReward(reward)
	rewardEst := status.EstimateTSReward(rewardNorm, pr[0])
	// Update
	status.Reward.EstimatedRewardGenerate += rewardEst
	status.Reward.RewardAllTasks.Update(reward, 0.0)
	status.Reward.RawAllTasks.Update(cov, time)
}

func (status *MABStatus) UpdateMutateWeight(result mab.ExecResult, pr []float64) {
	cov := float64(result.Cov)
	time := result.TimeExec
	pidx := result.Pidx
	if pidx < 0 || pidx > len(status.fuzzer.corpus) {
		log.Logf(MABLogLevel, "MAB Error: pidx = %v out of range\n", pidx)
		return
	}
	if status.TSEnabled {
		p := status.fuzzer.corpus[pidx]
		mutateCnt := p.CorpusReward.MutateCount
		timeVerify := p.CorpusReward.VerifyTime
		timeMinimize := p.CorpusReward.MinimizeTime
		covMinimize := p.CorpusReward.MinimizeCov
		// After this mutation, total coverage gain by mutating this seed
		totalCovMutCur := p.CorpusReward.MutateCov + cov
		// After this mutation, total time cost of mutating this seed
		totalTimeMutCur := p.CorpusReward.MutateTime + time
		// Before this mutation, reward for mutating this seed
		rewardMutPrev := p.CorpusReward.MutateReward
		// Before this mutation, reward for triaging this seed
		rewardTriPrev := p.CorpusReward.TriageReward
		timeSave := p.CorpusReward.MinimizeTimeSave
		// Total estimated time save due to minimization
		totalTimeSave := float64(mutateCnt) * timeSave
		if totalTimeMutCur+timeVerify == 0.0 {
			log.Logf(MABLogLevel,
				"MAB Error: timeVerify(%v) + timeMut(%v) == 0\n",
				timeVerify, totalTimeMutCur)
			// Update raw coverage and time for future reward computation and normalization
			status.Reward.RawAllTasks.Update(cov, time)
			status.Reward.RawMutateOnly.Update(cov, time)
			return
		}
		// Distribut gain considering minimize effect
		// Minimize reward: Coverage/time reward + time saved
		rewardMinimizeCov := status.ComputeTSReward(covMinimize, timeMinimize)
		rewardMinimizeCur := rewardMinimizeCov + totalTimeSave
		log.Logf(MABLogLevel, "MAB Assoc Minimize Reward: %v + %v * %v = %v\n",
			rewardMinimizeCov, mutateCnt, timeSave, rewardMinimizeCur)
		// Verification reward: Partial mutation coverage vs verification time
		assocCovVerify := totalCovMutCur * timeVerify / (totalTimeMutCur + timeVerify)
		rewardVerifyCur := status.ComputeTSReward(assocCovVerify, timeVerify)
		log.Logf(MABLogLevel, "MAB Assoc Verify Reward: R((%v + %v) * %v / %v = %v, %v) = %v",
			status.fuzzer.corpus[pidx].CorpusReward.MutateCov, cov,
			timeVerify, totalTimeMutCur+timeVerify, assocCovVerify, timeVerify, rewardVerifyCur)
		// Triage reward: minimize + triage
		rewardTriageCurrent := rewardVerifyCur + rewardMinimizeCur
		log.Logf(MABLogLevel, "MAB Triage Reward: %v + %v = %v",
			rewardVerifyCur, rewardMinimizeCur, rewardTriageCurrent)
		// Mutation reward: Share partial mutation coverage to verification.
		assocCovMutCur := totalCovMutCur * totalTimeMutCur / (totalTimeMutCur + timeVerify)
		rewardMutCur := status.ComputeTSReward(assocCovMutCur, totalTimeMutCur)
		log.Logf(MABLogLevel,
			"MAB Mutate Reward: R((%v + %v) * (%v + %v) / %v = %v, %v) = %v\n",
			p.CorpusReward.MutateCov, cov, p.CorpusReward.MutateTime, time,
			totalTimeMutCur+timeVerify, assocCovMutCur, totalTimeMutCur, rewardMutCur)
		// Compute x
		rewardMutDiff := rewardMutCur - rewardMutPrev
		rewardTriDiff := rewardTriageCurrent - rewardTriPrev
		log.Logf(MABLogLevel, "MAB Triage Reward Diff: %v - %v = %v\n",
			rewardTriageCurrent, rewardTriPrev, rewardTriDiff)
		log.Logf(MABLogLevel, "MAB Mutate Reward Diff: %v - %v = %v\n",
			rewardMutCur, rewardMutPrev, rewardMutDiff)
		rewardNormMutDiff := status.NormalizeTSReward(rewardMutDiff)
		rewardNormTriDiff := status.NormalizeTSReward(rewardTriDiff)
		rewardEstMut := status.EstimateTSReward(rewardNormMutDiff, pr[1])
		// Triage might be unavailable this time, as a result, compute triage's probality as if triage is available
		// Fortunately, we know that mutation is definitely available. Use that as an estimation
		rewardEstTri := status.EstimateTSReward(rewardNormTriDiff, pr[1])
		status.Reward.EstimatedRewardMutate += rewardEstMut
		status.Reward.EstimatedRewardTriage += rewardEstTri
		// Update program stat
		status.fuzzer.corpus[pidx].CorpusReward.MutateCov = totalCovMutCur
		status.fuzzer.corpus[pidx].CorpusReward.MutateTime = totalTimeMutCur
		status.fuzzer.corpus[pidx].CorpusReward.MutateReward = rewardMutCur
		status.fuzzer.corpus[pidx].CorpusReward.TriageReward = rewardTriageCurrent
		// Don't use associated gain for normalization
		rewardNoassocNorm := status.ComputeTSReward(cov, time)
		status.Reward.RewardAllTasks.Update(rewardNoassocNorm, 0.0)
	}
	// Mark for update
	status.CorpusUpdate[pidx] = 1
	// Update for seed selection MAB
	if status.SSEnabled {
		rewardSS := status.ComputeSSReward(cov, time)
		rewardSSNorm := status.NormalizeSSReward(rewardSS)
		rewardSSEst := status.EstimateSSReward(rewardSSNorm,
			status.fuzzer.corpusPrios[pidx]/status.fuzzer.sumPrios[len(status.fuzzer.sumPrios)-1])
		status.UpdateSeedWeight(pidx, rewardSSEst)
		status.Reward.RewardMutateOnly.Update(rewardSS, 0.0)
	}
	status.fuzzer.corpus[pidx].CorpusReward.MutateCount++
	sig := hash.Hash(status.fuzzer.corpus[pidx].Serialize())
	log.Logf(MABLogLevel, "MAB Mutate Count for %v(%v): %v\n",
		pidx, sig.String(), status.fuzzer.corpus[pidx].CorpusReward.MutateCount)
	status.Reward.RawAllTasks.Update(cov, time)
	status.Reward.RawMutateOnly.Update(cov, time)
}

func (status *MABStatus) UpdateWeight(itemType int, result interface{}, pr []float64) {
	// 0 = Generate, 1 = Mutate, 2 = Triage
	if itemType < 0 || itemType > 2 || len(pr) < 3 {
		log.Logf(MABLogLevel, "MAB Error: itemType = %v\n", itemType)
		return
	}
	if pr[itemType] == 0 {
		log.Logf(MABLogLevel, "MAB Error: pr[%v] = 0\n", itemType)
		return
	}
	status.MABMu.Lock()

	defer func() {
		log.Logf(MABLogLevel, "MAB Round %v GLC: %+v\n", status.Round, status.Reward)
		exp31Max := math.Max(status.Reward.EstimatedRewardGenerate,
			math.Max(status.Reward.EstimatedRewardMutate,
				status.Reward.EstimatedRewardTriage))
		exp31Min := math.Min(status.Reward.EstimatedRewardGenerate,
			math.Min(status.Reward.EstimatedRewardMutate,
				status.Reward.EstimatedRewardTriage))
		if exp31Max-exp31Min > status.Exp31Threshold ||
			exp31Max > status.Exp31Threshold ||
			math.Abs(exp31Min) > status.Exp31Threshold {
			status.Exp31Round++
			status.ResetTS()
			status.BootstrapExp31()
		}
		status.MABMu.Unlock()
	}()
	_result := PreprocessResult(result)
	if itemType == 0 && status.TSEnabled { // Generate
		_r, ok := _result.(mab.ExecResult)
		if !ok {
			return
		}
		status.UpdateGenerateWeight(_r, pr)
	} else if itemType == 1 { // Mutate
		_r, ok := _result.(mab.ExecResult)
		if !ok {
			return
		}
		status.UpdateMutateWeight(_r, pr)
	} else if itemType == 2 { // Triage
		_r, ok := _result.(mab.TriageResult)
		if !ok {
			return
		}
		status.UpdateTriageWeight(_r, pr)
	}
}
