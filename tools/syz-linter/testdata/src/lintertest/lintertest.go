// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lintertest

/* some comment */ // want "Use C-style comments // instead of /* */"
var comment = 1    /* some comment */ // want "Use C-style comments // instead of /* */"

func stringComparison() {
	str := ""
	if len(str) == 0 { // want "Compare string with \"\", don't compare len with 0"
	}
	if 0 != len(str) { // want "Compare string with \"\", don't compare len with 0"
	}
	if len(returnString()+"foo") > 0 { // want "Compare string with \"\", don't compare len with 0"
	}
}

func returnString() string { return "foo" }

//
// One space.
//  Two spaces.
//	One tab.
//		Two tabs.
//No space.			// want "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments"
//	  Tab and spaces.	// want "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments"
// 	Space and tab.		// want "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments"
func checkCommentSpace() {
}

func funcArgsGood(a, b int) (int, int) {
	return 0, 0
}

func funcArgsBad0(a int, b int) { // want "Use 'a, b int'"
}

func funcArgsBad1() (a int, b int) { // want "Use 'a, b int'"
	return 0, 0
}

func funcArgsBad2(a int16, b, c uint32, d uint32, e int16) { // want "Use 'b, c, d uint32'"
}
