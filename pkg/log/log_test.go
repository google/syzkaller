// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package log

import (
	"testing"

	"github.com/stretchr/testify/require"
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
		Log(1, test.str)
		out := CachedLogOutput()
		if out != test.want {
			t.Fatalf("wrote: %v\nwant: %v\ngot: %v", test.str, test.want, out)
		}
	}
}

func TestLazy(t *testing.T) {
	// Ensure that the format message is formatted lazily only when logging enabled.
	Logf(1e6, "%v", noFormat{t})
}

type noFormat struct{ *testing.T }

func (nf noFormat) String() string {
	nf.T.Fatalf("must not be formatted")
	return ""
}

func TestVerboseWriter(t *testing.T) {
	prependTime = false
	defer func() { prependTime = true }()
	w := VerboseWriter(1)
	n, err := w.Write([]byte("foo\n"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	n, err = w.Write([]byte("bar\r\n"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Contains(t, CachedLogOutput(), "foo\nbar\n")
}
