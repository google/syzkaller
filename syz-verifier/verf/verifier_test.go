// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package verf

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

func makeResult(pool int, errnos []int, flags []int) *Result {
	r := &Result{Pool: pool, Info: ipc.ProgInfo{Calls: []ipc.CallInfo{}}}
	for i := range errnos {
		r.Info.Calls = append(r.Info.Calls, ipc.CallInfo{Errno: errnos[i], Flags: ipc.CallFlags(flags[i])})
	}
	return r
}

func TestVerify(t *testing.T) {
	p := "breaks_returns()\n" +
		"minimize$0(0x1, 0x1)\n" +
		"test$res0()\n"
	tests := []struct {
		name string
		res  []*Result
		want *ResultReport
	}{
		{
			name: "mismatches not found in results",
			res: []*Result{
				makeResult(2, []int{11, 33, 22}, []int{1, 3, 3}),
				makeResult(4, []int{11, 33, 22}, []int{1, 3, 3})},
			want: nil,
		},
		{
			name: "mismatches found in results",
			res: []*Result{
				makeResult(1, []int{1, 3, 2}, []int{1, 3, 7}),
				makeResult(4, []int{1, 3, 5}, []int{1, 3, 3}),
			},
			want: &ResultReport{
				Prog: p,
				Reports: []CallReport{
					{Call: "breaks_returns", Errnos: map[int]int{1: 1, 4: 1},
						Flags: map[int]ipc.CallFlags{1: 1, 4: 1}},
					{Call: "minimize$0", Errnos: map[int]int{1: 3, 4: 3},
						Flags: map[int]ipc.CallFlags{1: 3, 4: 3}},
					{Call: "test$res0", Errnos: map[int]int{1: 2, 4: 5},
						Flags: map[int]ipc.CallFlags{1: 7, 4: 3}, Mismatch: true},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := prog.InitTargetTest(t, "test", "64")
			prog, err := target.Deserialize([]byte(p), prog.Strict)
			if err != nil {
				t.Fatalf("failed to deserialise test program: %v", err)
			}
			got := Verify(test.res, prog)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Verify mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
