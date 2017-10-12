// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
)

func TestCompileAll(t *testing.T) {
	eh := func(pos ast.Pos, msg string) {
		t.Logf("%v: %v", pos, msg)
	}
	desc := ast.ParseGlob(filepath.Join("..", "..", "sys", "linux", "*.txt"), eh)
	if desc == nil {
		t.Fatalf("parsing failed")
	}
	glob := filepath.Join("..", "..", "sys", "linux", "*_"+runtime.GOARCH+".const")
	consts := DeserializeConstsGlob(glob, eh)
	if consts == nil {
		t.Fatalf("reading consts failed")
	}
	prog := Compile(desc, consts, targets.List["linux"]["amd64"], eh)
	if prog == nil {
		t.Fatalf("compilation failed")
	}
}

func TestErrors(t *testing.T) {
	consts := map[string]uint64{
		"__NR_foo": 1,
		"C0":       0,
		"C1":       1,
		"C2":       2,
	}
	target := targets.List["linux"]["amd64"]
	for _, name := range []string{"errors.txt", "errors2.txt"} {
		name := name
		t.Run(name, func(t *testing.T) {
			em := ast.NewErrorMatcher(t, filepath.Join("testdata", name))
			desc := ast.Parse(em.Data, name, em.ErrorHandler)
			if desc == nil {
				em.DumpErrors(t)
				t.Fatalf("parsing failed")
			}
			ExtractConsts(desc, target, em.ErrorHandler)
			Compile(desc, consts, target, em.ErrorHandler)
			em.Check(t)
		})
	}
}

func TestFuzz(t *testing.T) {
	inputs := []string{
		"d~^gB̉`i\u007f?\xb0.",
		"da[",
		"define\x98define(define\x98define\x98define\x98define\x98define)define\tdefin",
		"resource g[g]",
	}
	consts := map[string]uint64{"A": 1, "B": 2, "C": 3, "__NR_C": 4}
	eh := func(pos ast.Pos, msg string) {
		t.Logf("%v: %v", pos, msg)
	}
	for _, data := range inputs {
		desc := ast.Parse([]byte(data), "", eh)
		if desc != nil {
			Compile(desc, consts, targets.List["linux"]["amd64"], eh)
		}
	}
}

func TestAlign(t *testing.T) {
	const input = `
foo$0(a ptr[in, s0])
s0 {
	f0	int8
	f1	int16
}

foo$1(a ptr[in, s1])
s1 {
	f0	ptr[in, s2, opt]
}
s2 {
	f1	s1
	f2	array[s1, 2]
	f3	array[array[s1, 2], 2]
}
	`
	desc := ast.Parse([]byte(input), "input", nil)
	if desc == nil {
		t.Fatal("failed to parse")
	}
	p := Compile(desc, map[string]uint64{"__NR_foo": 1}, targets.List["linux"]["amd64"], nil)
	if p == nil {
		t.Fatal("failed to compile")
	}
	got := p.StructDescs[0].Desc
	t.Logf("got: %#v", got)
}
