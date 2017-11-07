// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package git

import (
	"testing"
)

func TestCanonicalizeCommit(t *testing.T) {
	tests := map[string]string{
		"foo bar":                     "foo bar",
		" foo ":                       "foo",
		"UPSTREAM: foo bar":           "foo bar",
		"BACKPORT: UPSTREAM: foo bar": "UPSTREAM: foo bar",
	}
	for in, want := range tests {
		got := CanonicalizeCommit(in)
		if got != want {
			t.Errorf("input %q: got %q, want %q", in, got, want)
		}
	}
}
