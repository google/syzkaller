// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import "testing"

func TestMatchFilename(t *testing.T) {
	sc := selectorCommon{}
	type Test struct {
		file1 string
		file2 string
		devID int
		match bool
	}
	tests := []Test{
		{
			"/dev/zero", "/dev/zero", -1, true,
		}, {
			"/dev/loop#", "/dev/loop1", 1, true,
		}, {
			"", "a", -1, false,
		}, {
			"/dev/loop#/loop", "/dev/loop0/looq", -1, false,
		}, {
			"/dev/i2c-#\x00", "/dev/i2c-1", 1, true,
		}, {
			"/dev/some#/some#", "/dev/some1/some1", 11, true,
		}, {
			"/dev/some/some#", "/dev/some", -1, false,
		}, {
			"/dev/some", "/dev/some/some", -1, false,
		},
	}
	for _, test := range tests {
		match, devID := sc.matchFilename([]byte(test.file1), []byte(test.file2))
		if test.match != match || test.devID != devID {
			t.Errorf("failed to match %s and %s\nexpected: %t, %d\n\ngot: %t, %d\n",
				test.file1, test.file2, test.match, test.devID, match, devID)
		}
	}
}
