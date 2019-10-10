// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"sort"
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
		"SYS_foo": 1,
		"C0":      0,
		"C1":      1,
		"C2":      2,
	}
	for _, name := range []string{"all.txt"} {
		for _, arch := range []string{"32_shmem", "64"} {
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
	for _, arch := range []string{"32_shmem", "64"} {
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
		"SYS_foo": 1,
		"C0":      0,
		"C1":      1,
		"C2":      2,
	}
	for _, arch := range []string{"32_shmem", "64"} {
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

func TestWarnings(t *testing.T) {
	t.Parallel()
	consts := map[string]uint64{
		"SYS_foo": 1,
	}
	for _, arch := range []string{"32_shmem", "64"} {
		target := targets.List["test"][arch]
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			em := ast.NewErrorMatcher(t, filepath.Join("testdata", "warnings.txt"))
			desc := ast.Parse(em.Data, "warnings.txt", em.ErrorHandler)
			if desc == nil {
				em.DumpErrors(t)
				t.Fatalf("parsing failed")
			}
			info := ExtractConsts(desc, target, em.ErrorHandler)
			if info == nil {
				em.DumpErrors(t)
				t.Fatalf("const extraction failed")
			}
			p := Compile(desc, consts, target, em.ErrorHandler)
			if p == nil {
				em.DumpErrors(t)
				t.Fatalf("compilation failed")
			}
			em.Check(t)
		})
	}
}

func TestFuzz(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		"d~^gB̉`i\u007f?\xb0.",
		"da[",
		"define\x98define(define\x98define\x98define\x98define\x98define)define\tdefin",
		"resource g[g]",
		`t[
l	t
]`,
		`t()D[0]
type D[e]l`,
		"E",
		"#",
		`
type p b[L]
type b[L] {
	e b[L[L]]
}`,
	} {
		Fuzz([]byte(data)[:len(data):len(data)])
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
	p := Compile(desc, map[string]uint64{"SYS_foo": 1}, targets.List["test"]["64"], nil)
	if p == nil {
		t.Fatal("failed to compile")
	}
	got := p.StructDescs[0].Desc
	t.Logf("got: %#v", got)
}

func TestCollectUnusedError(t *testing.T) {
	t.Parallel()
	const input = `
		s0 {
			f0 fidl_string
		}
        `
	nopErrorHandler := func(pos ast.Pos, msg string) {}
	desc := ast.Parse([]byte(input), "input", nopErrorHandler)
	if desc == nil {
		t.Fatal("failed to parse")
	}

	_, err := CollectUnused(desc, targets.List["test"]["64"], nopErrorHandler)
	if err == nil {
		t.Fatal("CollectUnused should have failed but didn't")
	}
}

func TestCollectUnused(t *testing.T) {
	t.Parallel()
	inputs := []struct {
		text  string
		names []string
	}{
		{
			text: `
				s0 {
					f0 string
				}
			`,
			names: []string{"s0"},
		},
		{
			text: `
				foo$0(a ptr[in, s0])
				s0 {
					f0	int8
					f1	int16
				}
			`,
			names: []string{},
		},
		{
			text: `
				s0 {
					f0	int8
					f1	int16
				}
				s1 {
					f2      int32
				}
				foo$0(a ptr[in, s0])
			`,
			names: []string{"s1"},
		},
	}

	for i, input := range inputs {
		desc := ast.Parse([]byte(input.text), "input", nil)
		if desc == nil {
			t.Fatalf("Test %d: failed to parse", i)
		}

		nodes, err := CollectUnused(desc, targets.List["test"]["64"], nil)
		if err != nil {
			t.Fatalf("Test %d: CollectUnused failed: %v", i, err)
		}

		if len(input.names) != len(nodes) {
			t.Errorf("Test %d: want %d nodes, got %d", i, len(input.names), len(nodes))
		}

		names := make([]string, len(nodes))
		for i := range nodes {
			_, _, names[i] = nodes[i].Info()
		}

		sort.Strings(names)
		sort.Strings(input.names)

		if !reflect.DeepEqual(names, input.names) {
			t.Errorf("Test %d: Unused nodes differ. Want %v, Got %v", i, input.names, names)
		}
	}
}
