// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"os"
	"strconv"
)

type token int

const (
	tokIllegal token = iota
	tokComment
	tokIdent
	tokInclude
	tokIncdir
	tokDefine
	tokResource
	tokString
	tokCExpr
	tokInt

	tokNewLine
	tokLParen
	tokRParen
	tokLBrack
	tokRBrack
	tokLBrace
	tokRBrace
	tokEq
	tokComma
	tokColon

	tokEOF
)

var punctuation = [256]token{
	'\n': tokNewLine,
	'(':  tokLParen,
	')':  tokRParen,
	'[':  tokLBrack,
	']':  tokRBrack,
	'{':  tokLBrace,
	'}':  tokRBrace,
	'=':  tokEq,
	',':  tokComma,
	':':  tokColon,
}

var tok2str = [...]string{
	tokIllegal:  "ILLEGAL",
	tokComment:  "comment",
	tokIdent:    "identifier",
	tokInclude:  "include",
	tokIncdir:   "incdir",
	tokDefine:   "define",
	tokResource: "resource",
	tokString:   "string",
	tokCExpr:    "CEXPR",
	tokInt:      "int",
	tokNewLine:  "NEWLINE",
	tokEOF:      "EOF",
}

func init() {
	for ch, tok := range punctuation {
		if tok == tokIllegal {
			continue
		}
		tok2str[tok] = fmt.Sprintf("%q", ch)
	}
}

var keywords = map[string]token{
	"include":  tokInclude,
	"incdir":   tokIncdir,
	"define":   tokDefine,
	"resource": tokResource,
}

func (tok token) String() string {
	return tok2str[tok]
}

type scanner struct {
	data         []byte
	filename     string
	errorHandler ErrorHandler

	ch   byte
	off  int
	line int
	col  int

	prev1 token
	prev2 token

	errors int
}

func newScanner(data []byte, filename string, errorHandler ErrorHandler) *scanner {
	if errorHandler == nil {
		errorHandler = LoggingHandler
	}
	s := &scanner{
		data:         data,
		filename:     filename,
		errorHandler: errorHandler,
		off:          -1,
	}
	s.next()
	return s
}

type ErrorHandler func(pos Pos, msg string)

func LoggingHandler(pos Pos, msg string) {
	fmt.Fprintf(os.Stderr, "%v: %v\n", pos, msg)
}

func (pos Pos) String() string {
	return fmt.Sprintf("%v:%v:%v", pos.File, pos.Line, pos.Col)
}

func (s *scanner) Scan() (tok token, lit string, pos Pos) {
	s.skipWhitespace()
	pos = s.pos()
	switch {
	case s.ch == 0:
		tok = tokEOF
		s.next()
	case s.ch == '`':
		tok = tokCExpr
		for s.next(); s.ch != '`' && s.ch != '\n'; s.next() {
		}
		if s.ch == '\n' {
			s.Error(pos, "C expression is not terminated")
		} else {
			lit = string(s.data[pos.Off+1 : s.off])
			s.next()
		}
	case s.prev2 == tokDefine && s.prev1 == tokIdent:
		// Note: the old form for C expressions, not really lexable.
		// TODO(dvyukov): get rid of this eventually.
		tok = tokCExpr
		for ; s.ch != '\n'; s.next() {
		}
		lit = string(s.data[pos.Off:s.off])
	case s.ch == '#':
		tok = tokComment
		for s.next(); s.ch != '\n'; s.next() {
		}
		lit = string(s.data[pos.Off+1 : s.off])
	case s.ch == '"' || s.ch == '<':
		// TODO(dvyukov): get rid of <...> strings, that's only includes
		tok = tokString
		closing := byte('"')
		if s.ch == '<' {
			closing = '>'
		}
		for s.next(); s.ch != closing; s.next() {
			if s.ch == 0 || s.ch == '\n' {
				s.Error(pos, "string literal is not terminated")
				return
			}
		}
		lit = string(s.data[pos.Off+1 : s.off])
		for i := 0; i < len(lit); i++ {
			if lit[i] < 0x20 || lit[i] >= 0x80 {
				pos1 := pos
				pos1.Col += i + 1
				pos1.Off += i + 1
				s.Error(pos1, "illegal character %#U in string literal", lit[i])
				break
			}
		}
		if lit == "" {
			// Currently unsupported because with the current Type representation
			// it would not be possible to understand if it is an empty string
			// or a 0 integer.
			s.Error(pos, "empty string literals are not supported")
		}
		s.next()
	case s.ch >= '0' && s.ch <= '9':
		tok = tokInt
		for s.ch >= '0' && s.ch <= '9' ||
			s.ch >= 'a' && s.ch <= 'f' ||
			s.ch >= 'A' && s.ch <= 'F' || s.ch == 'x' {
			s.next()
		}
		lit = string(s.data[pos.Off:s.off])
		bad := false
		if _, err := strconv.ParseUint(lit, 10, 64); err != nil {
			if len(lit) > 2 && lit[0] == '0' && lit[1] == 'x' {
				if _, err := strconv.ParseUint(lit[2:], 16, 64); err != nil {
					bad = true
				}
			} else {
				bad = true
			}
		}
		if bad {
			s.Error(pos, fmt.Sprintf("bad integer %q", lit))
			lit = "0"
		}
	case s.ch == '_' || s.ch >= 'a' && s.ch <= 'z' || s.ch >= 'A' && s.ch <= 'Z':
		tok = tokIdent
		for s.ch == '_' || s.ch == '$' ||
			s.ch >= 'a' && s.ch <= 'z' ||
			s.ch >= 'A' && s.ch <= 'Z' ||
			s.ch >= '0' && s.ch <= '9' {
			s.next()
		}
		lit = string(s.data[pos.Off:s.off])
		if key, ok := keywords[lit]; ok {
			tok = key
		}
	default:
		tok = punctuation[s.ch]
		if tok == tokIllegal {
			s.Error(pos, "illegal character %#U", s.ch)
		}
		s.next()
	}
	s.prev2 = s.prev1
	s.prev1 = tok
	return
}

func (s *scanner) Error(pos Pos, msg string, args ...interface{}) {
	s.errors++
	s.errorHandler(pos, fmt.Sprintf(msg, args...))
}

func (s *scanner) Ok() bool {
	return s.errors == 0
}

func (s *scanner) next() {
	s.off++
	for s.off < len(s.data) && s.data[s.off] == '\r' {
		s.off++
	}
	if s.off == len(s.data) {
		// Always emit NEWLINE before EOF.
		// Makes lots of things simpler as we always
		// want to treat EOF as NEWLINE as well.
		s.ch = '\n'
		s.off++
		return
	}
	if s.off > len(s.data) {
		s.ch = 0
		return
	}
	if s.off == 0 || s.data[s.off-1] == '\n' {
		s.line++
		s.col = 0
	}
	s.ch = s.data[s.off]
	s.col++
	if s.ch == 0 {
		s.Error(s.pos(), "illegal character \\x00")
	}
}

func (s *scanner) skipWhitespace() {
	for s.ch == ' ' || s.ch == '\t' {
		s.next()
	}
}

func (s *scanner) pos() Pos {
	return Pos{
		File: s.filename,
		Off:  s.off,
		Line: s.line,
		Col:  s.col,
	}
}
