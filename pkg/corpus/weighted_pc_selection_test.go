// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
)

func TestWeightedPCSelection(t *testing.T) {
	// Redesign test to avoid code duplication with TestRandomPCSelection.
	// Scenario:
	// Prog A covers PC 100.
	// Prog B covers PC 100, 200.
	// Prog C covers PC 200.
	//
	// Counts:
	// PC 100: A, B (2 programs) -> Weight 0.5
	// PC 200: B, C (2 programs) -> Weight 0.5
	// Total Weight: 1.0
	//
	// Selection Prob (PC):
	// PC 100: 0.5
	// PC 200: 0.5
	//
	// Prog Selection via PC 100 (0.5 chance):
	//   A: 0.5 * 0.5 = 0.25
	//   B: 0.5 * 0.5 = 0.25
	//
	// Prog Selection via PC 200 (0.5 chance):
	//   B: 0.5 * 0.5 = 0.25
	//   C: 0.5 * 0.5 = 0.25
	//
	// Expected Total Probabilities:
	// A: 0.25
	// B: 0.25 + 0.25 = 0.50
	// C: 0.25

	selection := NewWeightedPCSelection()
	r := rand.New(testutil.RandSource(t))

	progA := &prog.Prog{}
	progB := &prog.Prog{}
	progC := &prog.Prog{}

	// Save programs with dummy signal.
	const sigLen = 1
	selection.SaveProgram(progA, signal.FromRaw([]uint64{0xA}, sigLen), []uint64{100})
	selection.SaveProgram(progB, signal.FromRaw([]uint64{0xB}, sigLen), []uint64{100, 200})
	selection.SaveProgram(progC, signal.FromRaw([]uint64{0xC}, sigLen), []uint64{200})

	counts := make(map[*prog.Prog]int)
	const total = 100000
	for i := 0; i < total; i++ {
		p := selection.ChooseProgram(r)
		counts[p]++
	}

	// 25% ~ 25000
	assert.InDelta(t, 25000, counts[progA], 1000)
	// 50% ~ 50000
	assert.InDelta(t, 50000, counts[progB], 1000)
	// 25% ~ 25000
	assert.InDelta(t, 25000, counts[progC], 1000)
}

func TestWeightedPCSelectionMany(t *testing.T) {
	// Insert 200 PCs.
	selection := NewWeightedPCSelection().(*WeightedPCSelection)
	r := rand.New(testutil.RandSource(t))

	// Create dummy prog.
	p := &prog.Prog{}
	sig := signal.FromRaw([]uint64{1}, 1)

	// Insert in order.
	for i := 0; i < 200; i++ {
		selection.SaveProgram(p, sig, []uint64{uint64(i)})
	}

	// Verify internal slice structure.
	assert.Equal(t, 200, len(selection.tree))
	assert.Equal(t, 200, len(selection.pcMap))

	// Check sum (should be 200.0 as each weight is 1.0/1 = 1.0).
	assert.InDelta(t, 200.0, selection.tree[0].sum, 0.001)

	// Verify we can select every PC (implicitly).
	// Instead, just run many times and ensure we get p.
	for i := 0; i < 2000; i++ {
		res := selection.ChooseProgram(r)
		assert.Equal(t, p, res)
	}
}

func TestWeightedPCSelectionEmpty(t *testing.T) {
	selection := NewWeightedPCSelection()
	r := rand.New(testutil.RandSource(t))
	assert.Nil(t, selection.ChooseProgram(r))
}
