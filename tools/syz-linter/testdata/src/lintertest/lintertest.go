// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lintertest

import (
	"fmt"
	"log"
)

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
	checkCommentSpace() // lower-case comment is OK
	// Capital letter comment.
	checkCommentSpace()
	// Don't use 2 spaces after dot.  Like this.	// want "Use one space after a period"
	checkCommentSpace()
}

//No space.			// want "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments"

func funcArgsGood(a, b int) (int, int) {
	return 0, 0
}

func funcArgsBad0(a int, b int) { // want "Use 'a, b int'"
}

func funcArgsBad1() (a int, b int) { // want "Use 'a, b int'"
	return 0, 0	// lower-case comment is OK
}

func funcArgsBad2(a int16, b, c uint32, d uint32, e int16) { // want "Use 'b, c, d uint32'"
}

func logErrorMessages() {
	fmt.Errorf("good message")
	fmt.Errorf("good message %v", 0)
	msg := "good message"
	fmt.Errorf(msg)
	log.Printf("good message")
	log.Print("good message")
	log.Print("Using.An.Identifier is ok as well")
	log.Print(msg)

	fmt.Errorf("Bad message")	// want "Don't start log/error messages with a Capital letter"
	log.Fatalf("Bad message %v", 1) // want "Don't start log/error messages with a Capital letter"
	log.Printf("Bad message %v", 1) // want "Don't start log/error messages with a Capital letter"
	log.Print("Bad message") // want "Don't start log/error messages with a Capital letter"
	log.Print("also ad message.") // want "Don't use period at the end of log/error messages"
	log.Print("no new lines\n") // want "Don't use \\\\n at the end of log/error messages"
	log.Print("") // want "Don't use empty log/error messages"
}

func varDecls() {
	var a int
	b := 0
	c := int64(0)
	var _ int = 0
	var d int = 0	// want "Don't use both var, type and value in variable declarations"
	_, _, _, _ = a, b, c, d
}
