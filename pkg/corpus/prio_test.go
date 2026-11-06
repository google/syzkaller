// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/signal"
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

func TestChooseProgramExistingItemUpdate(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	inp1 := generateRangedInput(target, rs, 1, 10)
	inp2 := generateRangedInput(target, rs, 11, 20)
	corpus.Save(inp1)
	corpus.Save(inp2)
	// inp1 gives 20 more signal on re-execution, so its priority grows from 10 to 30.
	upd := inp1
	upd.Signal = signal.FromRaw(makeRange(21, 40), 0)
	corpus.Save(upd)
	assert.Equal(t, int64(40), corpus.sumPrios)

	shares := chooseShares(corpus, r)
	assert.InDelta(t, 0.75, shares[inp1.Prog], 0.05)
	assert.InDelta(t, 0.25, shares[inp2.Prog], 0.05)
}

// chooseShares returns the share of ChooseProgram() calls that returned each program.
func chooseShares(corpus *Corpus, r *rand.Rand) map[*prog.Prog]float64 {
	const iters = 10000
	shares := make(map[*prog.Prog]float64)
	for range iters {
		shares[corpus.ChooseProgram(r)] += 1.0 / iters
	}
	return shares
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
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}},
			Weight:   1.0,
		},
	})

	// inp1 has 100 global signal entries, but only 1 PC in the focus area.
	inp1 := generateRangedInput(target, rs, 1, 100)
	inp1.Cover = []uint64{10}

	// inp2 has only 2 global signal entries, but both of its PCs are in the focus area.
	inp2 := generateRangedInput(target, rs, 101, 102)
	inp2.Cover = []uint64{10, 11}

	corpus.Save(inp1)
	corpus.Save(inp2)

	verifySampling := func(stage string) {
		shares := chooseShares(corpus, rnd)
		// PC 10 is covered by both programs and PC 11 only by inp2, so PC 10 contributes
		// half as much as PC 11: inp2 should be chosen ~75% of the time, inp1 ~25%.
		// Under the old bug (len(signal)), inp1 would be chosen ~98% of the time.
		assert.InDelta(t, 0.75, shares[inp2.Prog], 0.05, stage)
		assert.InDelta(t, 0.25, shares[inp1.Prog], 0.05, stage)
	}

	verifySampling("before minimization")
	corpus.Minimize(true)
	verifySampling("after minimization")
}

func TestFocusAreaPCRarity(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	// Save 100 programs that all cover the same 4 hot PCs (10..13),
	// and then 1 program that covers 2 rare PCs (20, 21).
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

	verifySampling := func(stage string) {
		shares := chooseShares(corpus, rnd)
		// Despite 100 programs covering {10..13}, the single program covering {20, 21}
		// keeps a large selection share, and the first hot program has no insertion-order advantage.
		assert.Greater(t, shares[rare.Prog], 0.25, stage)
		assert.Less(t, shares[firstHot], 0.02, stage)
	}
	verifySampling("before minimization")
	corpus.Minimize(true)
	verifySampling("after minimization")
}

func TestFocusAreaExistingItemUpdate(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "patch",
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}},
			Weight:   1.0,
		},
	})
	inp1 := generateRangedInput(target, rs, 1, 1)
	inp1.Cover = []uint64{10}
	inp2 := generateRangedInput(target, rs, 2, 2)
	inp2.Cover = []uint64{10}
	corpus.Save(inp1)
	corpus.Save(inp2)

	// The same program covers a new focus PC on re-execution.
	upd := inp1
	upd.Signal = signal.FromRaw([]uint64{3}, 0)
	upd.Cover = []uint64{10, 11}
	corpus.Save(upd)

	shares := chooseShares(corpus, rnd)
	assert.InDelta(t, 0.75, shares[inp1.Prog], 0.05)
	assert.InDelta(t, 0.25, shares[inp2.Prog], 0.05)
}

func TestFocusedPrograms(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{Name: "focused", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 1.0},
		{Name: "zero", CoverPCs: map[uint64]struct{}{20: {}}, Weight: 0},
		{Weight: 1.0},
	})
	focused := generateRangedInput(target, rs, 1, 1)
	focused.Cover = []uint64{10, 20}
	zero := generateRangedInput(target, rs, 2, 2)
	zero.Cover = []uint64{20}
	other := generateRangedInput(target, rs, 3, 3)
	other.Cover = []uint64{30}
	corpus.Save(focused)
	corpus.Save(zero)
	corpus.Save(other)

	verify := func(stage string) {
		assert.Equal(t, []*prog.Prog{focused.Prog}, corpus.FocusedPrograms(), stage)
		chosen := make(map[int]int)
		for range 1000 {
			chosen[len(corpus.ChoosePrograms(rnd))]++
		}
		// ChoosePrograms returns either the "focused" area (1 program), or the "zero" area
		// (never, since its weight is 0), or the whole corpus (3 programs).
		assert.Len(t, chosen, 2, stage)
		assert.InDelta(t, 500, chosen[1], 100, stage)
		assert.InDelta(t, 500, chosen[3], 100, stage)
	}
	verify("before minimization")
	corpus.Minimize(true)
	verify("after minimization")
}
