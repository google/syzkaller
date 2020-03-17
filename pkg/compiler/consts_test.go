// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
)

func TestExtractConsts(t *testing.T) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", "consts.txt"))
	if err != nil {
		t.Fatalf("failed to read input file: %v", err)
	}
	desc := ast.Parse(data, "consts.txt", nil)
	if desc == nil {
		t.Fatalf("failed to parse input")
	}
	target := targets.List["linux"]["amd64"]
	fileInfo := ExtractConsts(desc, target, func(pos ast.Pos, msg string) {
		t.Fatalf("%v: %v", pos, msg)
	})
	info := fileInfo["consts.txt"]
	if info == nil || len(fileInfo) != 1 {
		t.Fatalf("bad file info returned: %+v", info)
	}
	wantConsts := []string{
		"__NR_bar", "__NR_foo",
		"CONST1", "CONST2", "CONST3", "CONST4", "CONST5",
		"CONST6", "CONST7", "CONST8", "CONST9", "CONST10",
		"CONST11", "CONST12", "CONST13", "CONST14", "CONST15",
		"CONST16", "CONST17", "CONST18", "CONST19", "CONST20",
		"CONST21", "CONST22", "CONST23", "CONST24", "CONST25",
		"CONST26",
	}
	sort.Strings(wantConsts)
	if !reflect.DeepEqual(info.Consts, wantConsts) {
		t.Fatalf("got consts:\n%q\nwant:\n%q", info.Consts, wantConsts)
	}
	wantIncludes := []string{"foo/bar.h", "bar/foo.h"}
	if !reflect.DeepEqual(info.Includes, wantIncludes) {
		t.Fatalf("got includes:\n%q\nwant:\n%q", info.Includes, wantIncludes)
	}
	wantIncdirs := []string{"/foo", "/bar"}
	if !reflect.DeepEqual(info.Incdirs, wantIncdirs) {
		t.Fatalf("got incdirs:\n%q\nwant:\n%q", info.Incdirs, wantIncdirs)
	}
	wantDefines := map[string]string{
		"CONST1": "1",
		"CONST2": "FOOBAR + 1",
	}
	if !reflect.DeepEqual(info.Defines, wantDefines) {
		t.Fatalf("got defines:\n%q\nwant:\n%q", info.Defines, wantDefines)
	}
}

func TestConstErrors(t *testing.T) {
	name := "consts_errors.txt"
	em := ast.NewErrorMatcher(t, filepath.Join("testdata", name))
	desc := ast.Parse(em.Data, name, em.ErrorHandler)
	if desc == nil {
		em.DumpErrors()
		t.Fatalf("parsing failed")
	}
	target := targets.List["linux"]["amd64"]
	ExtractConsts(desc, target, em.ErrorHandler)
	em.Check()
}
