// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/cover/backend"
)

func TestMergeDiff(t *testing.T) {
	type Test struct {
		init   []uint64
		merge  []uint64
		diff   []uint64
		result []uint64
	}
	tests := []Test{
		{
			init:   nil,
			merge:  nil,
			diff:   nil,
			result: []uint64{},
		},
		{
			init:   []uint64{0, 1, 3, 4},
			merge:  nil,
			diff:   nil,
			result: []uint64{0, 1, 3, 4},
		},
		{
			init:   nil,
			merge:  []uint64{0, 1, 3, 4},
			diff:   []uint64{0, 1, 3, 4},
			result: []uint64{0, 1, 3, 4},
		},
		{
			init:   []uint64{0, 1, 3, 4},
			merge:  []uint64{4, 7, 1, 9},
			diff:   []uint64{7, 9},
			result: []uint64{0, 1, 3, 4, 7, 9},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var cov Cover
			cov.Merge(test.init)
			diff := cov.MergeDiff(test.merge)
			if res := cmp.Diff(test.diff, diff); res != "" {
				t.Fatalf("result is wrong: %v", res)
			}
			result := cov.Serialize()
			sort.Slice(result, func(i, j int) bool {
				return result[i] < result[j]
			})
			if res := cmp.Diff(test.result, result); res != "" {
				t.Fatalf("resulting coverage is wrong: %v", res)
			}
		})
	}
}

func TestPerLineCoverage(t *testing.T) {
	const End = backend.LineEnd
	// Start line:col - end line:col.
	// nolint
	covered := []backend.Range{
		// Just covered.
		{1, 2, 1, 10},
		{2, 1, 4, 10},
		// Both covered and uncovered.
		{10, 0, 10, 10},
		{11, 20, 11, 30},
		{12, 0, 12, End},
		// Broken debug data.
		{30, 10, 29, 20},
		{31, 20, 30, 10},
		{32, 10, 32, 5},
		// Double covered.
		{40, 10, 40, 20},
		{40, 12, 40, 18},
		{41, 10, 41, 20},
		{41, 15, 41, 30},
		{42, 20, 42, 30},
		{42, 10, 42, 25},
	}
	// nolint
	uncovered := []backend.Range{
		{10, 20, 10, 30},
		{11, 0, 11, 20},
		{12, 0, 12, End},
		// Only uncovered.
		{20, 20, 21, 10},
	}
	want := map[int][]lineCoverChunk{
		1:  {{2, false, false}, {10, true, false}, {End, false, false}},
		2:  {{1, false, false}, {End, true, false}},
		3:  {{End, true, false}},
		4:  {{10, true, false}, {End, false, false}},
		10: {{10, true, false}, {20, false, false}, {30, false, true}, {End, false, false}},
		11: {{20, false, true}, {30, true, false}, {End, false, false}},
		12: {{End, true, true}},
		20: {{20, false, false}, {End, false, true}},
		21: {{10, false, true}, {End, false, false}},
		30: {{10, false, false}, {20, true, false}, {End, false, false}},
		31: {{20, false, false}, {End, true, false}},
		32: {{10, false, false}, {End, true, false}},
		40: {{10, false, false}, {20, true, false}, {End, false, false}},
		41: {{10, false, false}, {20, true, false}, {30, true, false}, {End, false, false}},
		42: {{10, false, false}, {20, true, false}, {30, true, false}, {End, false, false}},
	}
	got := perLineCoverage(covered, uncovered)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}
