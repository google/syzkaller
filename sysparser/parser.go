// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sysparser

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type parser struct {
	r *bufio.Scanner
	s string
	i int
	l int
}

func newParser(r io.Reader) *parser {
	return &parser{r: bufio.NewScanner(r)}
}

func (p *parser) Scan() bool {
	if !p.r.Scan() {
		if err := p.r.Err(); err != nil {
			failf("failed to read input file: %v", err)
		}
		return false
	}
	p.s = p.r.Text()
	p.i = 0
	p.l++
	return true
}

func (p *parser) Str() string {
	return p.s
}

func (p *parser) EOF() bool {
	return p.i == len(p.s)
}

func (p *parser) Char() byte {
	if p.EOF() {
		p.failf("unexpected eof")
	}
	return p.s[p.i]
}

func (p *parser) Parse(ch byte) {
	if p.EOF() {
		p.failf("want %s, got EOF", string(ch))
	}
	if p.s[p.i] != ch {
		p.failf("want '%v', got '%v'", string(ch), string(p.s[p.i]))
	}
	p.i++
	p.SkipWs()
}

func (p *parser) SkipWs() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) Ident() string {
	start, end := p.i, 0
	if p.Char() == '"' {
		p.Parse('"')
		for p.Char() != '"' {
			p.i++
		}
		end = p.i + 1
		p.Parse('"')
	} else {
		for p.i < len(p.s) &&
			(p.s[p.i] >= 'a' && p.s[p.i] <= 'z' ||
				p.s[p.i] >= 'A' && p.s[p.i] <= 'Z' ||
				p.s[p.i] >= '0' && p.s[p.i] <= '9' ||
				p.s[p.i] == '_' || p.s[p.i] == '$' || // $ is for n-way syscalls (like ptrace$peek)
				p.s[p.i] == '-' || p.s[p.i] == ':') { // : is for ranged int (like int32[-3:10])
			p.i++
		}
		if start == p.i {
			p.failf("failed to parse identifier at pos %v", start)
		}
		end = p.i
	}
	s := p.s[start:end]
	p.SkipWs()
	return s
}

func (p *parser) failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "line #%v: %v\n", p.l, p.s)
	failf(msg, args...)
}
