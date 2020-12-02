// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func TestMatchDomains(t *testing.T) {
	type Test struct {
		self      string
		input     string
		minimized bool
		smashed   bool
	}
	tests := []Test{
		{"", "", true, true},
		{"linux", "", true, true},
		{"linux/", "", true, true},
		{"linux/upstream/kasan", "", true, true},
		{"", "linux", true, true},
		{"", "linux/", true, true},
		{"linux", "linux/", false, false},
		{"linux/", "linux/", false, false},
		{"linux", "linuz", true, true},
		{"linux/upstream/kasan", "linuz", true, true},
		{"linux/upstream", "linux/upstream", false, false},
		{"linux/upstream", "linux/upstreax", true, true},
		{"linux/upstream/", "linux/upstream", false, false},
		{"linux/upstream", "linux/upstreax/", true, true},
		{"linux/upstream", "linux/upstream/kasan", false, true},
		{"linux/upstream/kasan", "linux/upstream", false, true},
		{"linux/upstream/kasan", "linux/upstream/xasan", false, true},
		{"linux/upstream/kasan", "linux/upstream/kasan", false, false},
		{"linux/upstreax/kasan", "linux/upstream/kasan", true, true},
		{"linux/upstreax/kasan", "linux/upstream/xasan", true, true},
		{"linux/upstream/kasan", "linuz/upstream/xasan", true, true},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			minimized, smashed := matchDomains(test.self, test.input)
			if minimized != test.minimized || smashed != test.smashed {
				t.Fatalf("(%q, %q) = %v/%v, want %v/%v",
					test.self, test.input, minimized, smashed, test.minimized, test.smashed)
			}
		})
	}
}
