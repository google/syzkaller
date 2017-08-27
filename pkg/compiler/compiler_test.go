// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
)

func TestCompileAll(t *testing.T) {
	t.Skip()
	eh := func(pos ast.Pos, msg string) {
		t.Logf("%v: %v", pos, msg)
	}
	desc := ast.ParseGlob(filepath.Join("..", "..", "sys", "*.txt"), eh)
	if desc == nil {
		t.Fatalf("parsing failed")
	}
	glob := filepath.Join("..", "..", "sys", "*_"+runtime.GOARCH+".const")
	consts := DeserializeConstsGlob(glob, eh)
	if consts == nil {
		t.Fatalf("reading consts failed")
	}
	prog := Compile(desc, consts, eh)
	if prog == nil {
		t.Fatalf("compilation failed")
	}
}

func init() {
	typeCheck = true
}

func TestErrors(t *testing.T) {
	consts := map[string]uint64{
		"__NR_foo": 1,
	}
	name := "errors.txt"
	em := ast.NewErrorMatcher(t, filepath.Join("testdata", name))
	desc := ast.Parse(em.Data, name, em.ErrorHandler)
	if desc == nil {
		em.DumpErrors(t)
		t.Fatalf("parsing failed")
	}
	Compile(desc, consts, em.ErrorHandler)
	em.Check(t)
}
