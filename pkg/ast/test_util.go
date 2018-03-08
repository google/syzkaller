// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type ErrorMatcher struct {
	Data   []byte
	expect []*errorDesc
	got    []*errorDesc
}

type errorDesc struct {
	file    string
	line    int
	col     int
	text    string
	matched bool
}

func NewErrorMatcher(t *testing.T, file string) *ErrorMatcher {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatalf("failed to open input file: %v", err)
	}
	var stripped []byte
	var errors []*errorDesc
	s := bufio.NewScanner(bytes.NewReader(data))
	for i := 1; s.Scan(); i++ {
		ln := s.Bytes()
		for {
			pos := bytes.LastIndex(ln, []byte("###"))
			if pos == -1 {
				break
			}
			errors = append(errors, &errorDesc{
				file: filepath.Base(file),
				line: i,
				text: strings.TrimSpace(string(ln[pos+3:])),
			})
			ln = ln[:pos]
		}
		stripped = append(stripped, ln...)
		stripped = append(stripped, '\n')
	}
	if err := s.Err(); err != nil {
		t.Fatalf("failed to scan input file: %v", err)
	}
	return &ErrorMatcher{
		Data:   stripped,
		expect: errors,
	}
}

var errorLocationRe = regexp.MustCompile(`at [a-z][a-z0-9]+\.txt:[0-9]+:[0-9]+`)

func (em *ErrorMatcher) ErrorHandler(pos Pos, msg string) {
	if match := errorLocationRe.FindStringSubmatchIndex(msg); match != nil {
		msg = msg[0:match[0]] + "at LOCATION" + msg[match[1]:]
	}
	em.got = append(em.got, &errorDesc{
		file: pos.File,
		line: pos.Line,
		col:  pos.Col,
		text: msg,
	})
}

func (em *ErrorMatcher) Count() int {
	return len(em.got)
}

func (em *ErrorMatcher) Check(t *testing.T) {
nextErr:
	for _, e := range em.got {
		for _, want := range em.expect {
			if want.matched || want.line != e.line || want.text != e.text {
				continue
			}
			want.matched = true
			continue nextErr
		}
		t.Errorf("unexpected error:\n%v:%v:%v: %v", e.file, e.line, e.col, e.text)
	}
	for _, want := range em.expect {
		if want.matched {
			continue
		}
		t.Errorf("unmatched error:\n%v:%v: %v", want.file, want.line, want.text)
	}
}

func (em *ErrorMatcher) DumpErrors(t *testing.T) {
	for _, e := range em.got {
		t.Logf("%v:%v:%v: %v", e.file, e.line, e.col, e.text)
	}
}
