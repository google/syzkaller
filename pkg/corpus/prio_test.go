// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)

	priorities := make(map[*prog.Prog]int64)
	for i := range sizeCorpus {
		sizeSig := i + 1
		if sizeSig%250 == 0 {
			sizeSig = 0
		}
		inp := generateInput(target, rs, sizeSig)
		corpus.Save(inp)
		priorities[inp.Prog] = int64(len(inp.Signal))
	}
	counters := make(map[*prog.Prog]int)
	for range maxIters {
		counters[corpus.chooseProgram(r)]++
	}
	for p, prio := range priorities {
		prob := float64(prio) / float64(corpus.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
		}
	}
}

func TestFocusAreas(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			CoverPCs: map[uint64]struct{}{
				0: {},
				1: {},
			},
			Weight: 10,
		},
		{
			CoverPCs: map[uint64]struct{}{
				2: {},
				3: {},
			},
			Weight: 30,
		},
		{
			// An empty CoverPCs filter matches the whole corpus.
			Weight: 60,
		},
	})

	rs := rand.NewSource(0)

	fillGroup := func(from, to, count int) map[*prog.Prog]bool {
		ret := map[*prog.Prog]bool{}
		for i := range count {
			a := from + i%(to-from+1)
			b := a + i%(to-a+1)
			inp := generateRangedInput(target, rs, a, b)
			ret[inp.Prog] = true
			corpus.Save(inp)
		}
		return ret
	}

	first := fillGroup(0, 1, 10)
	second := fillGroup(2, 3, 10)
	third := fillGroup(4, 5, 10)

	rnd := rand.New(rs)
	different := map[*prog.Prog]bool{}
	firstCount, secondCount, thirdCount := 0, 0, 0
	const TOTAL = 10000
	for range TOTAL {
		p := corpus.ChooseProgram(rnd)
		different[p] = true

		if first[p] {
			firstCount++
		} else if second[p] {
			secondCount++
		} else if third[p] {
			thirdCount++
		}
	}

	assert.Greater(t, len(different), 25)
	// The third area (weight 60%) covers all 3 groups equally (20% each).
	assert.InDelta(t, firstCount, TOTAL*0.3, TOTAL/25)
	assert.InDelta(t, secondCount, TOTAL*0.5, TOTAL/25)
	assert.InDelta(t, thirdCount, TOTAL*0.2, TOTAL/25)
}

func TestFocusAreaInAreaWeighting(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "patch",
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}, 12: {}},
			Weight:   1.0,
		},
	})

	// inp1 has 100 global signal entries, but only 1 PC in the focus area.
	inp1 := generateRangedInput(target, rs, 1, 100)
	inp1.Cover = []uint64{10}

	// inp2 has only 2 global signal entries, but both of its PCs are in the focus area.
	inp2 := generateRangedInput(target, rs, 101, 102)
	inp2.Cover = []uint64{11, 12}

	corpus.Save(inp1)
	corpus.Save(inp2)

	verifySampling := func(stage string) {
		counts := make(map[*prog.Prog]int)
		const iters = 10000
		for range iters {
			counts[corpus.ChooseProgram(rnd)]++
		}
		// inp2 has 2 focus PCs, inp1 has 1 focus PC.
		// inp2 should be chosen ~2/3 (66.7%) of the time, inp1 ~1/3 (33.3%).
		// Under the old bug (len(signal)), inp1 would be chosen ~98% of the time.
		assert.InDelta(t, 2.0/3.0, float64(counts[inp2.Prog])/iters, 0.05, stage)
		assert.InDelta(t, 1.0/3.0, float64(counts[inp1.Prog])/iters, 0.05, stage)
	}

	verifySampling("before minimization")
	corpus.Minimize(true)
	verifySampling("after minimization")
}

func TestFocusAreaPCRaritySaturation(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	// Save 100 redundant programs that all cover the same 4 hot PCs (10..13),
	// plus 1 program that covers 2 rare PCs (20, 21) AND was added after the 100 redundant ones.
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "symbols",
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}, 12: {}, 13: {}, 20: {}, 21: {}},
			Weight:   1.0,
		},
	})
	var firstHot *prog.Prog
	for i := range 100 {
		inp := generateRangedInput(target, rs, i+1, i+1)
		inp.Cover = []uint64{10, 11, 12, 13}
		if i == 0 {
			firstHot = inp.Prog
		}
		corpus.Save(inp)
	}

	rare := generateRangedInput(target, rs, 200, 200)
	rare.Cover = []uint64{10, 20, 21}
	corpus.Save(rare)

	rareCount := 0
	firstHotCount := 0
	const iters = 10000
	for range iters {
		switch corpus.ChooseProgram(rnd) {
		case rare.Prog:
			rareCount++
		case firstHot:
			firstHotCount++
		}
	}
	// Despite 100 programs covering {10..13}, inverse-frequency PC weighting keeps the single
	// program covering {20, 21} above 25% selection share, and the first hot program does not
	// retain an insertion-order advantage.
	assert.Greater(t, float64(rareCount)/iters, 0.25)
	assert.Less(t, float64(firstHotCount)/iters, 0.02)
	assert.Contains(t, corpus.FocusedPrograms(), rare.Prog)
}
