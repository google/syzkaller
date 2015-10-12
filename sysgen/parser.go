// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type Parser struct {
	r *bufio.Scanner
	s string
	i int
	l int
}

func NewParser(r io.Reader) *Parser {
	return &Parser{r: bufio.NewScanner(r)}
}

func (p *Parser) Scan() bool {
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

func (p *Parser) Str() string {
	return p.s
}

func (p *Parser) EOF() bool {
	return p.i == len(p.s)
}

func (p *Parser) Char() byte {
	if p.EOF() {
		p.failf("unexpected eof")
	}
	return p.s[p.i]
}

func (p *Parser) Parse(ch byte) {
	if p.EOF() {
		p.failf("want %s, got EOF", string(ch))
	}
	if p.s[p.i] != ch {
		p.failf("want '%v', got '%v'", string(ch), string(p.s[p.i]))
	}
	p.i++
	p.SkipWs()
}

func (p *Parser) SkipWs() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *Parser) Ident() string {
	i := p.i
	for p.i < len(p.s) &&
		(p.s[p.i] >= 'a' && p.s[p.i] <= 'z' ||
			p.s[p.i] >= 'A' && p.s[p.i] <= 'Z' ||
			p.s[p.i] >= '0' && p.s[p.i] <= '9' ||
			p.s[p.i] == '_' || p.s[p.i] == '$') { // $ is for n-way syscalls (like ptrace$peek)
		p.i++
	}
	if i == p.i {
		p.failf("failed to parse identifier at pos %v", i)
	}
	if ch := p.s[i]; ch >= '0' && ch <= '9' {
		// p.failf("identifier starts with a digit at pos %v", i)
	}
	s := p.s[i:p.i]
	p.SkipWs()
	return s
}

func (p *Parser) failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "line #%v: %v\n", p.l, p.s)
	failf(msg, args...)
}
