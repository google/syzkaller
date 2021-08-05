// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/prog"
)

func TestVerify(t *testing.T) {
	p := "breaks_returns()\n" +
		"minimize$0(0x1, 0x1)\n" +
		"test$res0()\n"
	tests := []struct {
		name       string
		res        []*Result
		wantReport *ResultReport
		wantStats  []*CallStats
	}{
		{
			name: "only crashes",
			res: []*Result{
				makeResultCrashed(1),
				makeResultCrashed(4),
			},
			wantReport: nil,
		},
		{
			name: "mismatches because results and crashes",
			res: []*Result{
				makeResultCrashed(1),
				makeResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
				makeResult(4, []int{11, 33, 22}, []int{1, 3, 3}...),
			},
			wantReport: &ResultReport{
				Prog: p,
				Reports: []*CallReport{
					{Call: "breaks_returns", States: map[int]ReturnState{
						1: crashedReturnState(),
						2: returnState(11, 1),
						4: returnState(11, 1)},
						Mismatch: true},
					{Call: "minimize$0", States: map[int]ReturnState{
						1: crashedReturnState(),
						2: returnState(33, 3),
						4: returnState(33, 3)},
						Mismatch: true},
					{Call: "test$res0", States: map[int]ReturnState{
						1: crashedReturnState(),
						2: returnState(22, 3),
						4: returnState(22, 3)},
						Mismatch: true},
				},
			},
		},
		{
			name: "mismatches not found in results",
			res: []*Result{
				makeResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
				makeResult(4, []int{11, 33, 22}, []int{1, 3, 3}...)},
			wantReport: nil,
		},
		{
			name: "mismatches found in results",
			res: []*Result{
				makeResult(1, []int{1, 3, 2}, []int{4, 7, 7}...),
				makeResult(4, []int{1, 3, 5}, []int{4, 7, 3}...),
			},
			wantReport: &ResultReport{
				Prog: p,
				Reports: []*CallReport{
					{Call: "breaks_returns", States: map[int]ReturnState{1: {Errno: 1, Flags: 4}, 4: {Errno: 1, Flags: 4}}},
					{Call: "minimize$0", States: map[int]ReturnState{1: {Errno: 3, Flags: 7}, 4: {Errno: 3, Flags: 7}}},
					{Call: "test$res0", States: map[int]ReturnState{1: {Errno: 2, Flags: 7}, 4: {Errno: 5, Flags: 3}}, Mismatch: true},
				},
			},
		}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := prog.InitTargetTest(t, "test", "64")
			prog, err := target.Deserialize([]byte(p), prog.Strict)
			if err != nil {
				t.Fatalf("failed to deserialise test program: %v", err)
			}
			stats := emptyTestStats()
			got := Verify(test.res, prog, stats)
			if diff := cmp.Diff(test.wantReport, got); diff != "" {
				t.Errorf("Verify report mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
