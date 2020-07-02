// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lintertest

/* some comment */			// want "Use C-style comments // instead of /* */"
var comment = 1 /* some comment */	// want "Use C-style comments // instead of /* */"

func stringComparison() {
	str := ""
	if len(str) == 0 {}			// want "compare string with \"\", don't compare len with 0"
	if 0 != len(str) {}			// want "compare string with \"\", don't compare len with 0"
	if len(returnString() + "foo") > 0 {}	// want "compare string with \"\", don't compare len with 0"
}

func returnString() string { return "foo" }
