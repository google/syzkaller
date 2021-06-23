// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package verf

import (
	"testing"

	"github.com/google/syzkaller/pkg/ipc"
)

func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		res       []*Result
		wantMatch bool
	}{
		{

			name: "results should match",
			res: []*Result{
				{2, false, ipc.ProgInfo{
					Calls: []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 3}}, Extra: ipc.CallInfo{},
				},
				},
				{4, false, ipc.ProgInfo{
					Calls: []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 3}},
					Extra: ipc.CallInfo{},
				},
				},
			},

			wantMatch: true,
		},
		{
			name: "results should not match",
			res: []*Result{
				{4, false, ipc.ProgInfo{
					Calls: []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 5}},
				},
				},
				{8, false, ipc.ProgInfo{
					Calls: []ipc.CallInfo{{Errno: 1}, {Errno: 3}, {Errno: 5}},
				},
				},
			},
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := Verify(test.res, nil), test.wantMatch; got != want {
				t.Errorf("Verify: got %v, want %v", got, want)
			}
		})
	}
}

func TestVerifyErrno(t *testing.T) {
	tests := []struct {
		name      string
		c1, c2    []ipc.CallInfo
		wantMatch bool
	}{
		{
			name:      "errno should match",
			c1:        []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 5}},
			c2:        []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 5}},
			wantMatch: true,
		},
		{
			name:      "errno should not match",
			c1:        []ipc.CallInfo{{Errno: 1}, {Errno: 2}, {Errno: 5}},
			c2:        []ipc.CallInfo{{Errno: 1}, {Errno: 4}, {Errno: 5}},
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := VerifyErrnos(test.c1, test.c2), test.wantMatch; got != want {
				t.Errorf("VerifyErrno: got %v, want %v", got, want)
			}
		})
	}
}
