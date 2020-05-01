// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAll(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "sys", "linux", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("failed to read sys dir: %v", err)
	}
	files = append(files, filepath.FromSlash("testdata/all.txt"))
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		t.Run(file, func(t *testing.T) {
			eh := func(pos Pos, msg string) {
				t.Fatalf("%v: %v", pos, msg)
			}
			desc := Parse(data, file, eh)
			if desc == nil {
				t.Fatalf("parsing failed, but no error produced")
			}
			data2 := Format(desc)
			desc2 := Parse(data2, file, eh)
			if desc2 == nil {
				t.Fatalf("parsing failed, but no error produced")
			}
			if len(desc.Nodes) != len(desc2.Nodes) {
				t.Fatalf("formatting number of top level decls: %v/%v",
					len(desc.Nodes), len(desc2.Nodes))
			}
			for i := range desc.Nodes {
				n1, n2 := desc.Nodes[i], desc2.Nodes[i]
				if n1 == nil {
					t.Fatalf("got nil node")
				}
				if !reflect.DeepEqual(n1, n2) {
					t.Fatalf("formatting changed code:\n%#v\nvs:\n%#v", n1, n2)
				}
			}
			data3 := Format(desc.Clone())
			if !bytes.Equal(data, data3) {
				t.Fatalf("Clone lost data")
			}
			nodes0 := 0
			desc.Walk(func(n Node) {
				nodes0++
				if SerializeNode(n) == "" {
					t.Fatalf("empty serialized node: %#v", n)
				}
			})
			nodes1 := 0
			desc.Walk(Recursive(func(n Node) {
				nodes1++
				pos, typ, _ := n.Info()
				if typ == "" {
					t.Fatalf("%v: node has empty typ=%q: %#v", pos, typ, n)
				}
			}))
			nodes2 := 0
			desc.Walk(PostRecursive(func(n Node) {
				nodes2++
			}))
			if nodes0 != len(desc.Nodes) || nodes1 <= len(desc.Nodes) || nodes1 != nodes2 {
				t.Fatalf("bad walk: desc=%v, top=%v recursive=%v, postrecursive=%v",
					len(desc.Nodes), nodes0, nodes1, nodes2)
			}
			desc4 := desc.Filter(func(n Node) bool { return true })
			desc5 := desc.Filter(func(n Node) bool { return false })
			if len(desc4.Nodes) != len(desc.Nodes) || len(desc5.Nodes) != 0 {
				t.Fatalf("Filter is broken: desc=%v desc4=%v desc5=%v",
					len(desc.Nodes), len(desc4.Nodes), len(desc5.Nodes))
			}
		})
	}
}

func TestParse(t *testing.T) {
	for _, test := range parseTests {
		t.Run(test.name, func(t *testing.T) {
			errorHandler := func(pos Pos, msg string) {
				t.Logf("%v: %v", pos, msg)
			}
			Parse([]byte(test.input), "foo", errorHandler)
		})
	}
}

var parseTests = []struct {
	name   string
	input  string
	result []interface{}
}{
	{
		"empty",
		``,
		[]interface{}{},
	},
	{
		"new-line",
		`

`,
		[]interface{}{},
	},
	{
		"nil",
		"\x00",
		[]interface{}{},
	},
}

func TestErrors(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no input files")
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".txt") {
			continue
		}
		name := f.Name()
		t.Run(name, func(t *testing.T) {
			em := NewErrorMatcher(t, filepath.Join("testdata", name))
			desc := Parse(em.Data, name, em.ErrorHandler)
			if desc != nil && em.Count() != 0 {
				em.DumpErrors()
				t.Fatalf("parsing succeed, but got errors")
			}
			if desc == nil && em.Count() == 0 {
				t.Fatalf("parsing failed, but got no errors")
			}
			em.Check()
		})
	}
}
