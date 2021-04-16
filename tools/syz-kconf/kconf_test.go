// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func TestReleaseTag(t *testing.T) {
	type Test struct {
		in  string
		out string
		err bool
	}
	tests := []Test{
		{
			in: `
VERSION = 4
PATCHLEVEL = 19
SUBLEVEL = 144
EXTRAVERSION =
`,
			out: "v4.19",
		},
		{
			in: `
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 0
EXTRAVERSION =
`,
			out: "v5.4",
		},
		{
			in: `
VERSION = 5
PATCHLEVEL = 11
SUBLEVEL = 0
EXTRAVERSION = -rc3
`,
			out: "v5.11",
		},
		{
			in: `
PATCHLEVEL = 11
SUBLEVEL = 0
EXTRAVERSION = -rc3
`,
			err: true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got, err := releaseTagImpl([]byte(test.in))
			if test.err != (err != nil) {
				t.Fatalf("expected err=%v, got %q", test.err, err)
			}
			if test.out != got {
				t.Fatalf("expected release %q, got %q", test.out, got)
			}
		})
	}
}
