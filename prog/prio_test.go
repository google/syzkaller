// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNormalizePrio(t *testing.T) {
	prios := [][]float32{
		{2, 2, 2},
		{1, 2, 4},
		{1, 2, 0},
	}
	want := [][]float32{
		{1, 1, 1},
		{0.1, 0.4, 1},
		{0.4, 1, 0.1},
	}
	t.Logf("had:  %+v", prios)
	normalizePrio(prios)
	if !reflect.DeepEqual(prios, want) {
		t.Logf("got:  %+v", prios)
		t.Errorf("want: %+v", want)
	}
}

// TestPrioChoice tests that we select all syscalls with equal probability.
func TestPrioChoice(t *testing.T) {
	t.Parallel()
	target := &Target{
		Syscalls: []*Syscall{
			{ID: 0},
			{ID: 1},
			{ID: 2},
			{ID: 3},
		},
	}
	prios := [][]float32{
		{1, 1, 1, 1},
		{1, 1, 1, 1},
		{1, 1, 1, 1},
		{1, 1, 1, 1},
	}
	ct := target.BuildChoiceTable(prios, nil)
	r := rand.New(rand.NewSource(0))
	var res [4]int
	for i := 0; i < 10000; i++ {
		res[ct.Choose(r, 0)]++
	}
	// If this fails too frequently we can do some ranges, but for now it's just hardcoded.
	want := [4]int{2552, 2459, 2491, 2498}
	if diff := cmp.Diff(res, want); diff != "" {
		t.Fatal(diff)
	}
}
