// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lintertest

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/tool"
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

func funcArgsGood2(a []int, b ...int) {
}

func funcArgsBad0(a int, b int) { // want "Use 'a, b int'"
}

func funcArgsBad1() (a int, b int) { // want "Use 'a, b int'"
	return 0, 0 // lower-case comment is OK
}

func funcArgsBad2(a int16, b, c uint32, d uint32, e int16) { // want "Use 'b, c, d uint32'"
}

type Foo struct{}

func funcArgsBad3(s string, b *Foo, c *Foo) { // want "b, c \\*lintertest\\.Foo"
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
	tool.Fail(err)
	tool.Failf("good message")
	tool.Failf("good message %v", 0)

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
	tool.Failf("Bad message")                                           // want "Don't start log/error messages with a Capital letter"
}

func testMessages(t *testing.T) {
	t.Logf("good message %v", 1)
	t.Logf("Bad message %v", 1)     // want "Don't start log/error messages with a Capital letter"
	t.Errorf("bad message %v\n", 1) // want "Don't use \\\\n at the end of log/error messages"
	t.Fatalf("Bad message %v", 1)   // want "Don't start log/error messages with a Capital letter"
	t.Fatalf("PublicFunc is ok %v", 1)
}

func varDecls() {
	var a int
	b := 0
	c := int64(0)
	var _ int = 0
	var d int = 0 // want "Don't use both var, type and value in variable declarations"
	_, _, _, _ = a, b, c, d
}

func minmax() {
	x, y := 0, 0
	if x < y + 1 {		// want "Use max function instead"
		x = y + 1
	}
	if x >= y {		// want "Use max function instead"
		y = x
	}
	if x > 10 {		// want "Use min function instead"
		x = 10
	}
}

func loopvar() {
	s := []int{1, 2, 3}
	for i, v := range s {
		i, v := i, v // want "Don't duplicate loop variables.*"
		_, _ = i, v
	}
}

func anyInterface() interface{} {	// want "Use any instead of interface{}"
	var v interface{}		// want "Use any instead of interface{}"
	func(interface{}) {} (v)	// want "Use any instead of interface{}"
	var y any
	func(any) {} (y)
	return v
}

func contextArgsGood1(ctx context.Context) {
}

func contextArgsBad1(c context.Context) { // want "Context variable must be named 'ctx'"
}

func contextArgsBad2(a int, ctx context.Context) { // want "Context must be the first argument"
}

func contextArgsGood2(ctx context.Context, a int) {
}

func TestContextArgsGood(t *testing.T, ctx context.Context) {
}

func TestContextArgsBad1(t *testing.T, c context.Context) { // want "Context variable must be named 'ctx'"
}

func TestContextArgsBad2(t *testing.T, a int, ctx context.Context) { // want "Context must be the second argument"
}

func sliceClones() {
	var x []int
	i := 0
	_ = append([]int{}, i)
	_ = append([]int{}, x...)  // want "Use slices.Clone instead of append"
}

func sortUsage() {
	var strs []string
	sort.Strings(strs) // want "Use slices.Sort instead of sort.Strings"

	var ints []int
	sort.Slice(ints, func(i, j int) bool { // want "Use slices.Sort or slices.SortFunc instead of sort.Slice with a simple predicate"
		return ints[i] < ints[j]
	})

	type Item struct {
		Name string
	}
	var items []Item
	sort.Slice(items, func(i, j int) bool { // want "Use slices.Sort or slices.SortFunc instead of sort.Slice with a simple predicate"
		return items[i].Name < items[j].Name
	})

	sort.Slice(items, func(i, j int) bool { // want "Use slices.Sort or slices.SortFunc instead of sort.Slice with a simple predicate"
		return items[j].Name < items[i].Name
	})

	sort.Slice(ints, func(i, j int) bool { // want "Use slices.Sort or slices.SortFunc instead of sort.Slice with a simple predicate"
		return ints[i] > ints[j]
	})
}

func rangeOverIntegers() {
	for i := 0; i < 10; i++ { // want "Use range over integer instead of traditional for loop"
	}

	count := 10
	for i := 0; i < count; i++ { // want "Use range over integer instead of traditional for loop"
	}

	// Negative cases.
	for i := 1; i < 10; i++ {
	}
	for i := 0; i <= 10; i++ {
	}
	for i := 0; i < 10; i += 2 {
	}
	for i := 10; i > 0; i-- {
	}
}

func whileStyleLoops() {
	i := 0
	for i < 10 { // want "Consider using for i := 0; i < ...; { to scope the loop variable"
		i++
	}

	count := 10
	j := 0
	for j < count { // want "Consider using for j := 0; j < ...; { to scope the loop variable"
		j++
	}

	// Negative cases.
	k := 1
	for k < 10 {
		k++
	}

	l := 0
	for l <= 10 {
		l++
	}
}

func mapKeysExtraction() {
	m := make(map[string]int)
	var keys []string
	for k := range m { // want "Use maps.Keys and slices.Sort instead of a manual loop"
		keys = append(keys, k)
	}
	sort.Strings(keys) // want "Use slices.Sort instead of sort.Strings"
}

func mapKeysExtractionNoSort() {
	m := make(map[string]int)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
}

func stringsCut() {
	s := "foo/bar"
	if pos := strings.Index(s, "/"); pos != -1 { // want "Use strings.Cut instead of strings.Index/IndexByte and manual slicing"
		_ = s[:pos]
	}
	if pos := strings.IndexByte(s, '/'); pos != -1 { // want "Use strings.Cut instead of strings.Index/IndexByte and manual slicing"
		_ = s[:pos]
	}
	if pos := strings.Index(s, "/"); pos != -1 {
		// Just use pos, not for slicing.
		_ = pos
	}
}

// Missing empty lines between declarations.
func missingEmptyLine1() {
}
func missingEmptyLine2() { // want "Keep one empty line between top-level declarations"
}
type MissingEmptyLineStruct struct { // want "Keep one empty line between top-level declarations"
}

// Comment for func 3
func missingEmptyLine3() {
}

// Single-line functions can be grouped.
func grouped1() {}
func grouped2() {}
func grouped3() {}

func multiLineGrouped() {
}
func grouped4() {} // want "Keep one empty line between top-level declarations"

func grouped5() {}
func multiLineGrouped2() { // want "Keep one empty line between top-level declarations"
}

func twoEmptyLines1() {}


func twoEmptyLines2() {} // want "Keep one empty line between top-level declarations"

type groupedType1 struct {
}

// Stand-alone comment that is not groupedType2 Doc.

type groupedType2 struct {
}
