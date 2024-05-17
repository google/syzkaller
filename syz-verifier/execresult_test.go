// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/prog"
)

func TestIsEqual(t *testing.T) {
	tests := []struct {
		name string
		res  []*ExecResult
		want bool
	}{
		{
			name: "only crashes",
			res: []*ExecResult{
				makeExecResultCrashed(1),
				makeExecResultCrashed(4),
			},
			want: false,
		},
		{
			name: "mismatch because result and crash",
			res: []*ExecResult{
				makeExecResultCrashed(1),
				makeExecResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
			},
			want: false,
		},
		{
			name: "mismatches because of diffent length",
			res: []*ExecResult{
				makeExecResult(2, []int{11, 33}, []int{1, 3}...),
				makeExecResult(4, []int{11, 33, 22}, []int{1, 3, 3}...)},
			want: false,
		},
		{
			name: "mismatches not found",
			res: []*ExecResult{
				makeExecResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
				makeExecResult(4, []int{11, 33, 22}, []int{1, 3, 3}...)},
			want: true,
		},
		{
			name: "mismatches found in results",
			res: []*ExecResult{
				makeExecResult(1, []int{1, 3, 2}, []int{4, 7, 7}...),
				makeExecResult(4, []int{1, 3, 5}, []int{4, 7, 3}...),
			},
			want: false,
		}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.res[0].IsEqual(test.res[1])
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("ExecResult.IsEqual failure (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompareResults(t *testing.T) {
	p := "breaks_returns()\n" +
		"minimize$0(0x1, 0x1)\n" +
		"test$res0()\n"
	tests := []struct {
		name       string
		res        []*ExecResult
		wantReport *ResultReport
		wantStats  []*CallStats
	}{
		{
			name: "only crashes",
			res: []*ExecResult{
				makeExecResultCrashed(1),
				makeExecResultCrashed(4),
			},
			wantReport: &ResultReport{
				Prog: p,
				Reports: []*CallReport{
					{Call: "breaks_returns", States: map[int]ReturnState{
						1: crashedReturnState(),
						4: crashedReturnState()},
					},
					{Call: "minimize$0", States: map[int]ReturnState{
						1: crashedReturnState(),
						4: crashedReturnState()},
					},
					{Call: "test$res0", States: map[int]ReturnState{
						1: crashedReturnState(),
						4: crashedReturnState()},
					},
				},
				Mismatch: false,
			},
		},
		{
			name: "mismatches because results and crashes",
			res: []*ExecResult{
				makeExecResultCrashed(1),
				makeExecResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
				makeExecResult(4, []int{11, 33, 22}, []int{1, 3, 3}...),
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
				Mismatch: true,
			},
		},
		{
			name: "mismatches not found in results",
			res: []*ExecResult{
				makeExecResult(2, []int{11, 33, 22}, []int{1, 3, 3}...),
				makeExecResult(4, []int{11, 33, 22}, []int{1, 3, 3}...)},
			wantReport: &ResultReport{
				Prog: p,
				Reports: []*CallReport{
					{Call: "breaks_returns", States: map[int]ReturnState{2: {Errno: 11, Flags: 1}, 4: {Errno: 11, Flags: 1}}},
					{Call: "minimize$0", States: map[int]ReturnState{2: {Errno: 33, Flags: 3}, 4: {Errno: 33, Flags: 3}}},
					{Call: "test$res0", States: map[int]ReturnState{2: {Errno: 22, Flags: 3}, 4: {Errno: 22, Flags: 3}}},
				},
				Mismatch: false,
			},
		},
		{
			name: "mismatches found in results",
			res: []*ExecResult{
				makeExecResult(1, []int{1, 3, 2}, []int{4, 7, 7}...),
				makeExecResult(4, []int{1, 3, 5}, []int{4, 7, 3}...),
			},
			wantReport: &ResultReport{
				Prog: p,
				Reports: []*CallReport{
					{Call: "breaks_returns", States: map[int]ReturnState{1: {Errno: 1, Flags: 4}, 4: {Errno: 1, Flags: 4}}},
					{Call: "minimize$0", States: map[int]ReturnState{1: {Errno: 3, Flags: 7}, 4: {Errno: 3, Flags: 7}}},
					{Call: "test$res0", States: map[int]ReturnState{1: {Errno: 2, Flags: 7}, 4: {Errno: 5, Flags: 3}}, Mismatch: true},
				},
				Mismatch: true,
			},
		}}

	for _, test := range tests {
		test := test // TODO: remove for gover >= 1.22
		t.Run(test.name, func(t *testing.T) {
			target := prog.InitTargetTest(t, "test", "64")
			prog, err := target.Deserialize([]byte(p), prog.Strict)
			if err != nil {
				t.Fatalf("failed to deserialise test program: %v", err)
			}
			got := CompareResults(test.res, prog)
			if diff := cmp.Diff(test.wantReport, got); diff != "" {
				t.Errorf("verify report mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
