// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/serializer"
	"github.com/google/syzkaller/sys/targets"
)

var flagUpdate = flag.Bool("update", false, "reformat all.txt")

func TestCompileAll(t *testing.T) {
	for os, arches := range targets.List {
		os, arches := os, arches
		t.Run(os, func(t *testing.T) {
			t.Parallel()
			eh := func(pos ast.Pos, msg string) {
				t.Logf("%v: %v", pos, msg)
			}
			path := filepath.Join("..", "..", "sys", os)
			desc := ast.ParseGlob(filepath.Join(path, "*.txt"), eh)
			if desc == nil {
				t.Fatalf("parsing failed")
			}
			for arch, target := range arches {
				arch, target := arch, target
				t.Run(arch, func(t *testing.T) {
					t.Parallel()
					consts := DeserializeConstsGlob(filepath.Join(path, "*_"+arch+".const"), eh)
					if consts == nil {
						t.Fatalf("reading consts failed")
					}
					prog := Compile(desc, consts, target, eh)
					if prog == nil {
						t.Fatalf("compilation failed")
					}
				})
			}
		})
	}
}

func TestNoErrors(t *testing.T) {
	t.Parallel()
	consts := map[string]uint64{
		"__NR_foo": 1,
		"C0":       0,
		"C1":       1,
		"C2":       2,
	}
	for _, name := range []string{"all.txt"} {
		for _, arch := range []string{"32", "64"} {
			name, arch := name, arch
			t.Run(fmt.Sprintf("%v/%v", name, arch), func(t *testing.T) {
				t.Parallel()
				target := targets.List["test"][arch]
				eh := func(pos ast.Pos, msg string) {
					t.Logf("%v: %v", pos, msg)
				}
				fileName := filepath.Join("testdata", name)
				data, err := ioutil.ReadFile(fileName)
				if err != nil {
					t.Fatal(err)
				}
				astDesc := ast.Parse(data, name, eh)
				if astDesc == nil {
					t.Fatalf("parsing failed")
				}
				formatted := ast.Format(astDesc)
				if !bytes.Equal(data, formatted) {
					if *flagUpdate {
						ioutil.WriteFile(fileName, formatted, 0644)
					}
					t.Fatalf("description is not formatted")
				}
				constInfo := ExtractConsts(astDesc, target, eh)
				if constInfo == nil {
					t.Fatalf("const extraction failed")
				}
				desc := Compile(astDesc, consts, target, eh)
				if desc == nil {
					t.Fatalf("compilation failed")
				}
				if len(desc.Unsupported) != 0 {
					t.Fatalf("something is unsupported:\n%+v", desc.Unsupported)
				}
				out := new(bytes.Buffer)
				fmt.Fprintf(out, "\n\nRESOURCES:\n")
				serializer.Write(out, desc.Resources)
				fmt.Fprintf(out, "\n\nSTRUCTS:\n")
				serializer.Write(out, desc.StructDescs)
				fmt.Fprintf(out, "\n\nSYSCALLS:\n")
				serializer.Write(out, desc.Syscalls)
				if false {
					t.Log(out.String()) // useful for debugging
				}
			})
		}
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	for _, arch := range []string{"32", "64"} {
		target := targets.List["test"][arch]
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			em := ast.NewErrorMatcher(t, filepath.Join("testdata", "errors.txt"))
			desc := ast.Parse(em.Data, "errors.txt", em.ErrorHandler)
			if desc == nil {
				em.DumpErrors(t)
				t.Fatalf("parsing failed")
			}
			ExtractConsts(desc, target, em.ErrorHandler)
			em.Check(t)
		})
	}
}

func TestErrors2(t *testing.T) {
	t.Parallel()
	consts := map[string]uint64{
		"__NR_foo": 1,
		"C0":       0,
		"C1":       1,
		"C2":       2,
	}
	for _, arch := range []string{"32", "64"} {
		target := targets.List["test"][arch]
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			em := ast.NewErrorMatcher(t, filepath.Join("testdata", "errors2.txt"))
			desc := ast.Parse(em.Data, "errors2.txt", em.ErrorHandler)
			if desc == nil {
				em.DumpErrors(t)
				t.Fatalf("parsing failed")
			}
			info := ExtractConsts(desc, target, em.ErrorHandler)
			if info == nil {
				em.DumpErrors(t)
				t.Fatalf("const extraction failed")
			}
			Compile(desc, consts, target, em.ErrorHandler)
			em.Check(t)
		})
	}
}

func TestFuzz(t *testing.T) {
	t.Parallel()
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
			Compile(desc, consts, targets.List["test"]["64"], eh)
		}
	}
}

func TestAlign(t *testing.T) {
	t.Parallel()
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
	p := Compile(desc, map[string]uint64{"__NR_foo": 1}, targets.List["test"]["64"], nil)
	if p == nil {
		t.Fatal("failed to compile")
	}
	got := p.StructDescs[0].Desc
	t.Logf("got: %#v", got)
}
