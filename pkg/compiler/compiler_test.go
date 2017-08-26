// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
)

func TestExtractConsts(t *testing.T) {
	desc := ast.Parse([]byte(extractConstsInput), "test", nil)
	if desc == nil {
		t.Fatalf("failed to parse input")
	}
	consts, includes, incdirs, defines := ExtractConsts(desc)
	wantConsts := []string{"CONST1", "CONST10", "CONST11", "CONST12", "CONST13",
		"CONST14", "CONST15", "CONST16",
		"CONST2", "CONST3", "CONST4", "CONST5",
		"CONST6", "CONST7", "CONST8", "CONST9", "__NR_bar", "__NR_foo"}
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

bar$BAZ(x vma[opt], y vma[CONST8], z vma[CONST9:CONST10])
bar$QUX(s ptr[in, string["foo", CONST11]], x csum[s, pseudo, CONST12])
bar$FOO(x int8[8:CONST13], y int16be[CONST14:10], z intptr[CONST15:CONST16])
`
