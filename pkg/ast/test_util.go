// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type ErrorMatcher struct {
	t      *testing.T
	Data   []byte
	expect []*errorDesc
	got    []*errorDesc
}

type errorDesc struct {
	pos     Pos
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
				pos:  Pos{File: filepath.Base(file), Line: i},
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
		t:      t,
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
		pos:  pos,
		text: msg,
	})
}

func (em *ErrorMatcher) Count() int {
	return len(em.got)
}

func (em *ErrorMatcher) Check() {
	em.t.Helper()
	errors := make(map[Pos][]string)
nextErr:
	for _, e := range em.got {
		for _, want := range em.expect {
			if want.matched || want.pos.Line != e.pos.Line || want.text != e.text {
				continue
			}
			want.matched = true
			continue nextErr
		}
		pos := e.pos
		pos.Col = 0
		pos.Off = 0
		errors[pos] = append(errors[pos], fmt.Sprintf("unexpected: %v", e.text))
	}
	for _, want := range em.expect {
		if want.matched {
			continue
		}
		errors[want.pos] = append(errors[want.pos], fmt.Sprintf("unmatched : %v", want.text))
	}

	if len(errors) == 0 {
		return
	}
	type Sorted struct {
		pos  Pos
		msgs []string
	}
	sorted := []Sorted{}
	for pos, msgs := range errors {
		sorted = append(sorted, Sorted{pos, msgs})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].pos.less(sorted[j].pos)
	})
	buf := new(bytes.Buffer)
	for _, err := range sorted {
		if len(err.msgs) == 1 {
			fmt.Fprintf(buf, "%v: %v\n", err.pos, err.msgs[0])
			continue
		}
		sort.Strings(err.msgs)
		fmt.Fprintf(buf, "%v:\n\t%v\n", err.pos, strings.Join(err.msgs, "\n\t"))
	}
	em.t.Errorf("\n%s", buf.Bytes())
}

func (em *ErrorMatcher) DumpErrors() {
	em.t.Helper()
	for _, e := range em.got {
		em.t.Logf("%v: %v", e.pos, e.text)
	}
}
