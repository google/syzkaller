// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math"
	"math/rand"
	"testing"
)

func TestChoose(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	mab := MultiArmedBandit{
		Theta: 0.1,
	}
	const (
		maxIters   = 1000
		numChoices = 3
		eps        = 0.001
		epsChoose  = 0.05
	)
	weights := [numChoices]float64{1.0, 2.0, 3.0}
	sumWeights := [numChoices]float64{1.0, 3.0, 6.0}
	probs := [numChoices]float64{1.0 / 6.0, 2.0 / 6.0, 3.0 / 6.0}
	// Forcibly initialize MAB choices.
	for i := 0; i < numChoices; i++ {
		newChoice := Choice{
			weight:     weights[i],
			sumWeights: sumWeights[i],
		}
		mab.Choices = append(mab.Choices, newChoice)
	}
	// Make choices.
	counters := [numChoices]int{0, 0, 0}
	for it := 0; it < maxIters; it++ {
		idx, pr := mab.Choose(r)
		if math.Abs(pr-probs[idx]) > eps {
			t.Fatalf("incorrect probability (%v) for %v. expecting %v +- %v", pr, idx, probs[idx], eps)
		}
		counters[idx]++
	}
	// Count result.
	for i := 0; i < numChoices; i++ {
		diff := math.Abs(probs[i]*maxIters - float64(counters[i]))
		if diff > epsChoose*maxIters {
			t.Fatalf("the selection difference (%v) for %v is higher than %v", diff, i, epsChoose*maxIters)
		}
	}
}

func TestUpdate(t *testing.T) {
	mab := MultiArmedBandit{
		Theta: 0.1,
	}
	const (
		numIters   = 5
		numChoices = 3
		eps        = 0.001
	)
	// Add new choices and check Gamma and Eta values.
	expectedEta := [numChoices]float64{
		0.0,           // 0.1 * sqrt(2 * ln(1) / 1)
		0.08325546111, // 0.1 * sqrt(2 * ln(2) / 2)
		0.08558085022, // 0.1 * sqrt(2 * ln(3) / 3)
	}
	expectedGamma := [numChoices]float64{
		0.0,           // 0.1 * sqrt(2 * ln(1) / 1) / 2
		0.04162773055, // 0.1 * sqrt(2 * ln(2) / 2) / 2
		0.04279042511, // 0.1 * sqrt(2 * ln(3) / 3) / 2
	}
	for c := 0; c < numChoices; c++ {
		ret := mab.NewChoice()
		if ret != c {
			t.Fatalf("error adding new choice %v. got return value %v", c, ret)
		}
		// Check sumWeights computation
		if math.Abs(mab.Choices[ret].sumWeights-(1.0*float64(c+1))) > eps {
			t.Fatalf("incorrect sumWeights (%v) after adding choice %v. expecting %v +- %v.",
				mab.Choices[ret].sumWeights, c, 1.0*float64(c+1), eps)
		}
		// Check whether Eta and Gamma are updated correctly.
		if math.Abs(mab.Eta-expectedEta[c]) > eps {
			t.Fatalf("incorrect eta (%v) after adding choice %v. expecting %v +- %v.", mab.Eta, c, expectedEta[c], eps)
		}
		if math.Abs(mab.Gamma-expectedGamma[c]) > eps {
			t.Fatalf("incorrect gamma (%v) after adding choice %v. expecting %v +- %v.", mab.Gamma, c, expectedGamma[c], eps)
		}
	}
	// Parameters sent to mab.Update().
	choices := [numIters]int{0, 0, 1, 2, 0}
	rewards := [numIters]float64{0.2, 0.4, 2.0, -2.0, -1.0}
	probs := [numIters]float64{0.3, 0.5, 0.3, 0.5, 0.9}
	// Expected status.
	expectedRewards := [numIters][numChoices]float64{
		{0.049931, 0.0, 0.0},            // [0] + (eta * 0.2 / (0.3 + gamma))
		{0.112999, 0.0, 0.0},            // [0] + (eta * 0.4 / (0.5 + gamma))
		{0.112999, 0.249659, 0.0},       // [1] + (eta * 1.0 / (0.3 + gamma))
		{0.112999, 0.249659, -0.157668}, // [2] + (eta * -1.0 / (0.5 + gamma))
		{0.022225, 0.249659, -0.157668}, // [0] + (eta * -1.0 / (0.9 + gamma))
	}
	expectedWeights := [numIters][numChoices]float64{
		{1.051199, 1.0, 1.0},
		{1.119631, 1.0, 1.0},
		{1.119631, 1.283588, 1.0},
		{1.119631, 1.283588, 0.854133},
		{1.022474, 1.283588, 0.854133},
	}
	expectedSumWeights := [numIters][numChoices]float64{
		{1.051199, 2.051199, 3.051199},
		{1.119631, 2.119631, 3.119631},
		{1.119631, 2.403219, 3.403219},
		{1.119631, 2.403219, 3.257352},
		{1.022474, 2.306062, 3.160195},
	}
	// Update.
	for i := 0; i < numIters; i++ {
		mab.Update(choices[i], rewards[i], probs[i])
		for c := 0; c < numChoices; c++ {
			if math.Abs(mab.Choices[c].reward-expectedRewards[i][c]) > eps {
				t.Fatalf("incorrect reward (%v) for choice %v after iteration %v. expecting %v +- %v.",
					mab.Choices[c].reward, c, i, expectedRewards[i][c], eps)
			}
			if math.Abs(mab.Choices[c].weight-expectedWeights[i][c]) > eps {
				t.Fatalf("incorrect weight (%v) for choice %v after iteration %v. expecting %v +- %v.",
					mab.Choices[c].weight, c, i, expectedWeights[i][c], eps)
			}
			if math.Abs(mab.Choices[c].sumWeights-expectedSumWeights[i][c]) > eps {
				t.Fatalf("incorrect sumWeights (%v) for choice %v after iteration %v. expecting %v +- %v.",
					mab.Choices[c].sumWeights, c, i, expectedSumWeights[i][c], eps)
			}
		}
	}
}

func TestInvalidUpdate(t *testing.T) {
	mab := MultiArmedBandit{
		Theta: 0.1,
	}
	mab.NewChoice()
	mab.NewChoice()
	// Non-exist
	mab.Update(2, 1.0, 1.0)
	// Zero probability
	mab.Update(0, 1.0, 0.0)
	if mab.Choices[0].reward != 0.0 {
		t.Fatalf("incorrect reward (%v). expecting zero", mab.Choices[0].reward)
	}
	// Exceeds max/min weight
	for i := 0; i < 10000; i++ {
		mab.Update(0, 1.0, 0.01)
		mab.Update(1, -1.0, 0.01)
	}
	weightThresholdMax := math.Exp(16)
	weightThresholdMin := math.Exp(-16)
	if mab.Choices[0].weight > weightThresholdMax {
		t.Fatalf("weight (%v) exceeds maximum threshold (%v)", mab.Choices[0].weight, weightThresholdMax)
	}
	if mab.Choices[1].weight < weightThresholdMin {
		t.Fatalf("weight (%v) exceeds minimum threshold (%v)", mab.Choices[1].weight, weightThresholdMin)
	}
}
