// Copyright 2024 syzkaller project authors. All rights reserved.
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

func TestRandomPCSelection(t *testing.T) {
	// Prog A covers PC 1, 2. Signal len 1.
	// Prog B covers PC 1. Signal len 1.
	// Prog C covers PC 3. Signal len 1.
	//
	// Selection probability:
	// PC 1 (1/3): A (0.5), B (0.5) -> A += 1/6, B += 1/6
	// PC 2 (1/3): A (1.0)          -> A += 1/3
	// PC 3 (1/3): C (1.0)          -> C += 1/3
	//
	// Expected:
	// A: 1/6 + 1/3 = 3/6 = 0.5
	// B: 1/6 = 0.166...
	// C: 1/3 = 0.333...

	selection := NewRandomPCSelection()

	progA := &prog.Prog{}
	progB := &prog.Prog{}
	progC := &prog.Prog{}

	r := rand.New(testutil.RandSource(t))
	selection.SaveProgram(progA, signal.FromRaw([]uint64{10}, 1), []uint64{1, 2})
	selection.SaveProgram(progB, signal.FromRaw([]uint64{10}, 1), []uint64{1})
	selection.SaveProgram(progC, signal.FromRaw([]uint64{10}, 1), []uint64{3})

	counts := make(map[*prog.Prog]int)
	total := 100000
	for i := 0; i < total; i++ {
		p := selection.ChooseProgram(r)
		counts[p]++
	}

	assert.InDelta(t, 50000, counts[progA], 1000)
	assert.InDelta(t, 16666, counts[progB], 1000)
	assert.InDelta(t, 33333, counts[progC], 1000)
}
