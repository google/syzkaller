// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"encoding/hex"
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
	tokStringHex
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
	tokIllegal:   "ILLEGAL",
	tokComment:   "comment",
	tokIdent:     "identifier",
	tokInclude:   "include",
	tokIncdir:    "incdir",
	tokDefine:    "define",
	tokResource:  "resource",
	tokString:    "string",
	tokStringHex: "hex string",
	tokCExpr:     "CEXPR",
	tokInt:       "int",
	tokNewLine:   "NEWLINE",
	tokEOF:       "EOF",
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

const BuiltinFile = "BUILTINS"

func (pos Pos) Builtin() bool {
	return pos.File == BuiltinFile
}

func (pos Pos) String() string {
	if pos.Builtin() {
		return "builtins"
	}
	if pos.Col == 0 {
		return fmt.Sprintf("%v:%v", pos.File, pos.Line)
	}
	return fmt.Sprintf("%v:%v:%v", pos.File, pos.Line, pos.Col)
}

func (pos Pos) less(other Pos) bool {
	if pos.File != other.File {
		return pos.File < other.File
	}
	if pos.Line != other.Line {
		return pos.Line < other.Line
	}
	return pos.Col < other.Col
}

func (s *scanner) Scan() (tok token, lit string, pos Pos) {
	s.skipWhitespace()
	pos = s.pos()
	switch {
	case s.ch == 0:
		tok = tokEOF
		s.next()
	case s.prev2 == tokDefine && s.prev1 == tokIdent:
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
		tok = tokString
		lit = s.scanStr(pos)
	case s.ch == '`':
		tok = tokStringHex
		lit = s.scanStr(pos)
	case s.ch >= '0' && s.ch <= '9' || s.ch == '-':
		tok = tokInt
		lit = s.scanInt(pos)
	case s.ch == '\'':
		tok = tokInt
		lit = s.scanChar(pos)
	case s.ch == '_' || s.ch >= 'a' && s.ch <= 'z' || s.ch >= 'A' && s.ch <= 'Z':
		tok, lit = s.scanIdent(pos)
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

func (s *scanner) scanStr(pos Pos) string {
	// TODO(dvyukov): get rid of <...> strings, that's only includes
	closing := s.ch
	if s.ch == '<' {
		closing = '>'
	}
	for s.next(); s.ch != closing; s.next() {
		if s.ch == 0 || s.ch == '\n' {
			s.Error(pos, "string literal is not terminated")
			return ""
		}
	}
	lit := string(s.data[pos.Off+1 : s.off])
	for i := 0; i < len(lit); i++ {
		if lit[i] < 0x20 || lit[i] >= 0x80 {
			pos1 := pos
			pos1.Col += i + 1
			pos1.Off += i + 1
			s.Error(pos1, "illegal character %#U in string literal", lit[i])
			break
		}
	}
	s.next()
	if closing != '`' {
		return lit
	}
	decoded, err := hex.DecodeString(lit)
	if err != nil {
		s.Error(pos, "bad hex string literal: %v", err)
	}
	return string(decoded)
}

func (s *scanner) scanInt(pos Pos) string {
	for s.ch >= '0' && s.ch <= '9' ||
		s.ch >= 'a' && s.ch <= 'f' ||
		s.ch >= 'A' && s.ch <= 'F' ||
		s.ch == 'x' || s.ch == '-' {
		s.next()
	}
	lit := string(s.data[pos.Off:s.off])
	if _, err := strconv.ParseUint(lit, 10, 64); err == nil {
		return lit
	}
	if len(lit) > 1 && lit[0] == '-' {
		if _, err := strconv.ParseInt(lit, 10, 64); err == nil {
			return lit
		}
	}
	if len(lit) > 2 && lit[0] == '0' && lit[1] == 'x' {
		if _, err := strconv.ParseUint(lit[2:], 16, 64); err == nil {
			return lit
		}
	}
	s.Error(pos, fmt.Sprintf("bad integer %q", lit))
	return "0"
}

func (s *scanner) scanChar(pos Pos) string {
	s.next()
	s.next()
	if s.ch != '\'' {
		s.Error(pos, "char literal is not terminated")
		return "0"
	}
	s.next()
	return string(s.data[pos.Off : pos.Off+3])
}

func (s *scanner) scanIdent(pos Pos) (tok token, lit string) {
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
