// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMergeDiff(t *testing.T) {
	type Test struct {
		init   []uint32
		merge  []uint32
		diff   []uint32
		result []uint32
	}
	tests := []Test{
		{
			init:   nil,
			merge:  nil,
			diff:   nil,
			result: []uint32{},
		},
		{
			init:   []uint32{0, 1, 3, 4},
			merge:  nil,
			diff:   nil,
			result: []uint32{0, 1, 3, 4},
		},
		{
			init:   nil,
			merge:  []uint32{0, 1, 3, 4},
			diff:   []uint32{0, 1, 3, 4},
			result: []uint32{0, 1, 3, 4},
		},
		{
			init:   []uint32{0, 1, 3, 4},
			merge:  []uint32{4, 7, 1, 9},
			diff:   []uint32{7, 9},
			result: []uint32{0, 1, 3, 4, 7, 9},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var cov Cover
			cov.Merge(test.init)
			diff := cov.MergeDiff(test.merge)
			if res := cmp.Diff(test.diff, diff); res != "" {
				t.Fatalf("MergeDiff result is wrong: %v", res)
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
