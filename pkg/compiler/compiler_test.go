// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
)

func TestExtractConsts(t *testing.T) {
	top, ok := ast.Parse([]byte(extractConstsInput), "test", nil)
	if !ok {
		t.Fatalf("failed to parse input")
	}
	consts, includes, incdirs, defines := ExtractConsts(top)
	wantConsts := []string{"CONST1", "CONST2", "CONST3", "CONST4", "CONST5",
		"CONST6", "CONST7", "__NR_bar", "__NR_foo"}
	if !reflect.DeepEqual(consts, wantConsts) {
		t.Fatalf("got consts:\n%q\nwant:\n%q", consts, wantConsts)
	}
	wantIncludes := []string{"foo/bar.h", "bar/foo.h"}
	if !reflect.DeepEqual(includes, wantIncludes) {
		t.Fatalf("got includes:\n%q\nwant:\n%q", includes, wantIncludes)
	}
	wantIncdirs := []string{"/foo", "/bar"}
	if !reflect.DeepEqual(incdirs, wantIncdirs) {
		t.Fatalf("got incdirs:\n%q\nwant:\n%q", incdirs, wantIncdirs)
	}
	wantDefines := map[string]string{
		"CONST1": "1",
		"CONST2": "FOOBAR + 1",
	}
	if !reflect.DeepEqual(defines, wantDefines) {
		t.Fatalf("got defines:\n%q\nwant:\n%q", defines, wantDefines)
	}
}

const extractConstsInput = `
include <foo/bar.h>
incdir </foo>
include <bar/foo.h>
incdir </bar>

flags = CONST3, CONST2, CONST1

define CONST1 1
define CONST2 FOOBAR + 1

foo(x const[CONST4]) ptr[out, array[int32, CONST5]]
bar$BAR()

str {
	f1	const[CONST6, int32]
	f2	array[array[int8, CONST7]]
}
`
