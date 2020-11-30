// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lintertest

import (
	"flag"
	"fmt"
	"log"
	"os"
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
	return 0, 0 // lower-case comment is OK
}

func funcArgsBad2(a int16, b, c uint32, d uint32, e int16) { // want "Use 'b, c, d uint32'"
}

func flagDefinitions() {
	flag.Int("good", 0, "fine description")
	flag.Int("camelCase", 0, "fine description") // want "Don't use Capital letters in flag names"
	flag.String("fine", "", "Capital Letter")    // want "Don't start flag description with a Capital letter"
	flag.Bool("fine", false, "dot at the end.")  // want "Don't use '.' at the end of flag description"
}

func logErrorMessages() {
	msg := "good message"
	err := fmt.Errorf("good message")
	fmt.Errorf("good message %v", 0)
	fmt.Errorf(msg)
	log.Printf("good message")
	log.Print("good message")
	log.Print("Using.An.Identifier is ok as well")
	log.Print(msg)
	fmt.Printf("%s", msg)
	fmt.Printf("fragment")
	fmt.Printf("Fragment Fragment %s", msg)
	fmt.Fprintf(nil, "These can be anything")

	fmt.Errorf("Bad message")                                           // want "Don't start log/error messages with a Capital letter"
	log.Fatalf("Bad message %v", 1)                                     // want "Don't start log/error messages with a Capital letter"
	log.Printf("Bad message %v", 1)                                     // want "Don't start log/error messages with a Capital letter"
	log.Print("Bad message")                                            // want "Don't start log/error messages with a Capital letter"
	log.Print("also ad message.")                                       // want "Don't use period at the end of log/error messages"
	log.Print("no new lines\n")                                         // want "Don't use \\\\n at the end of log/error messages"
	log.Print("")                                                       // want "Don't use empty log/error messages"
	fmt.Printf("Real output message with capital letter\n")             // want "Don't start log/error messages with a Capital letter"
	fmt.Printf("real output message without newline")                   // want "Add \\\\n at the end of printed messages"
	fmt.Fprintf(os.Stderr, "Real output message with capital letter\n") // want "Don't start log/error messages with a Capital letter"
	fmt.Fprintf(os.Stderr, "real output message without newline")       // want "Add \\\\n at the end of printed messages"
	fmt.Fprintf(os.Stderr, "%v", err)                                   // want "Add \\\\n at the end of printed messages"
}

func varDecls() {
	var a int
	b := 0
	c := int64(0)
	var _ int = 0
	var d int = 0 // want "Don't use both var, type and value in variable declarations"
	_, _, _, _ = a, b, c, d
}
