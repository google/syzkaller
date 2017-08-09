// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package log

import (
	"testing"
)

func init() {
	EnableLogCaching(4, 20)
}

func TestCaching(t *testing.T) {
	tests := []struct{ str, want string }{
		{"", ""},
		{"a", "a\n"},
		{"bb", "a\nbb\n"},
		{"ccc", "a\nbb\nccc\n"},
		{"dddd", "a\nbb\nccc\ndddd\n"},
		{"eeeee", "bb\nccc\ndddd\neeeee\n"},
		{"ffffff", "ccc\ndddd\neeeee\nffffff\n"},
		{"ggggggg", "eeeee\nffffff\nggggggg\n"},
		{"hhhhhhhh", "ggggggg\nhhhhhhhh\n"},
		{"jjjjjjjjjjjjjjjjjjjjjjjjj", "jjjjjjjjjjjjjjjjjjjjjjjjj\n"},
	}
	prependTime = false
	for _, test := range tests {
		Logf(1, test.str)
		out := CachedLogOutput()
		if out != test.want {
			t.Fatalf("wrote: %v\nwant: %v\ngot: %v", test.str, test.want, out)
		}
	}
}
