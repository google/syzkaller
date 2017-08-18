// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAll(t *testing.T) {
	dir := filepath.Join("..", "..", "sys")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read sys dir: %v", err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".txt") {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		errorHandler := func(pos Pos, msg string) {
			t.Fatalf("%v:%v:%v: %v", pos.File, pos.Line, pos.Col, msg)
		}
		top, ok := Parse(data, file.Name(), errorHandler)
		if !ok {
			t.Fatalf("parsing failed, but no error produced")
		}
		data2 := Format(top)
		top2, ok2 := Parse(data2, file.Name(), errorHandler)
		if !ok2 {
			t.Fatalf("parsing failed, but no error produced")
		}
		if len(top) != len(top2) {
			t.Fatalf("formatting number of top level decls: %v/%v", len(top), len(top2))
		}
		// While sys files are not formatted, formatting in fact changes it.
		for i := range top {
			if !reflect.DeepEqual(top[i], top2[i]) {
				t.Fatalf("formatting changed code:\n%#v\nvs:\n%#v", top[i], top2[i])
			}
		}
	}
}

func TestParse(t *testing.T) {
	for _, test := range parseTests {
		t.Run(test.name, func(t *testing.T) {
			errorHandler := func(pos Pos, msg string) {
				t.Logf("%v:%v:%v: %v", pos.File, pos.Line, pos.Col, msg)
			}
			toplev, ok := Parse([]byte(test.input), "foo", errorHandler)
			_, _ = toplev, ok
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

type Error struct {
	Line    int
	Col     int
	Text    string
	Matched bool
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
		t.Run(f.Name(), func(t *testing.T) {
			data, err := ioutil.ReadFile(filepath.Join("testdata", f.Name()))
			if err != nil {
				t.Fatalf("failed to open input file: %v", err)
			}
			var stripped []byte
			var errors []*Error
			s := bufio.NewScanner(bytes.NewReader(data))
			for i := 1; s.Scan(); i++ {
				ln := s.Bytes()
				for {
					pos := bytes.LastIndex(ln, []byte("###"))
					if pos == -1 {
						break
					}
					errors = append(errors, &Error{
						Line: i,
						Text: strings.TrimSpace(string(ln[pos+3:])),
					})
					ln = ln[:pos]
				}
				stripped = append(stripped, ln...)
				stripped = append(stripped, '\n')
			}
			if err := s.Err(); err != nil {
				t.Fatalf("failed to scan input file: %v", err)
			}
			var got []*Error
			top, ok := Parse(stripped, "test", func(pos Pos, msg string) {
				got = append(got, &Error{
					Line: pos.Line,
					Col:  pos.Col,
					Text: msg,
				})
			})
			if ok && len(got) != 0 {
				t.Fatalf("parsing succeed, but got errors: %v", got)
			}
			if !ok && len(got) == 0 {
				t.Fatalf("parsing failed, but got no errors")
			}
		nextErr:
			for _, gotErr := range got {
				for _, wantErr := range errors {
					if wantErr.Matched {
						continue
					}
					if wantErr.Line != gotErr.Line {
						continue
					}
					if wantErr.Text != gotErr.Text {
						continue
					}
					wantErr.Matched = true
					continue nextErr
				}
				t.Errorf("unexpected error: %v:%v: %v",
					gotErr.Line, gotErr.Col, gotErr.Text)
			}
			for _, wantErr := range errors {
				if wantErr.Matched {
					continue
				}
				t.Errorf("not matched error: %v: %v", wantErr.Line, wantErr.Text)
			}
			// Just to get more code coverage:
			Format(top)
		})
	}
}
