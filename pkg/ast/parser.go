// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
)

// Parse parses sys description into AST and returns top-level nodes.
// If any errors are encountered, returns nil.
func Parse(data []byte, filename string, errorHandler ErrorHandler) *Description {
	p := &parser{s: newScanner(data, filename, errorHandler)}
	prevNewLine, prevComment := false, false
	var top []Node
	for p.next(); p.tok != tokEOF; {
		decl := p.parseTopRecover()
		if decl == nil {
			continue
		}
		// Add new lines around structs, remove duplicate new lines.
		if _, ok := decl.(*NewLine); ok && prevNewLine {
			continue
		}
		if str, ok := decl.(*Struct); ok && !prevNewLine && !prevComment {
			top = append(top, &NewLine{Pos: str.Pos})
		}
		top = append(top, decl)
		if str, ok := decl.(*Struct); ok {
			decl = &NewLine{Pos: str.Pos}
			top = append(top, decl)
		}
		_, prevNewLine = decl.(*NewLine)
		_, prevComment = decl.(*Comment)
	}
	if prevNewLine {
		top = top[:len(top)-1]
	}
	if !p.s.Ok() {
		return nil
	}
	return &Description{top}
}

func ParseGlob(glob string, errorHandler ErrorHandler) *Description {
	if errorHandler == nil {
		errorHandler = LoggingHandler
	}
	files, err := filepath.Glob(glob)
	if err != nil {
		errorHandler(Pos{}, fmt.Sprintf("failed to find input files: %v", err))
		return nil
	}
	if len(files) == 0 {
		errorHandler(Pos{}, fmt.Sprintf("no files matched by glob %q", glob))
		return nil
	}
	desc := &Description{}
	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			errorHandler(Pos{}, fmt.Sprintf("failed to read input file: %v", err))
			return nil
		}
		desc1 := Parse(data, filepath.Base(f), errorHandler)
		if desc1 == nil {
			desc = nil
		}
		if desc != nil {
			desc.Nodes = append(desc.Nodes, desc1.Nodes...)
		}
	}
	return desc
}

type parser struct {
	s *scanner

	// Current token:
	tok token
	lit string
	pos Pos
}

// Skip parsing till the next NEWLINE, for error recovery.
var errSkipLine = errors.New("")

func (p *parser) parseTopRecover() Node {
	defer func() {
		switch err := recover(); err {
		case nil:
		case errSkipLine:
			// Try to recover by consuming everything until next NEWLINE.
			for p.tok != tokNewLine && p.tok != tokEOF {
				p.next()
			}
			p.tryConsume(tokNewLine)
		default:
			panic(err)
		}
	}()
	decl := p.parseTop()
	if decl == nil {
		panic("not reachable")
	}
	p.consume(tokNewLine)
	return decl
}

func (p *parser) parseTop() Node {
	switch p.tok {
	case tokNewLine:
		return &NewLine{Pos: p.pos}
	case tokComment:
		return p.parseComment()
	case tokDefine:
		return p.parseDefine()
	case tokInclude:
		return p.parseInclude()
	case tokIncdir:
		return p.parseIncdir()
	case tokResource:
		return p.parseResource()
	case tokIdent:
		name := p.parseIdent()
		if name.Name == "type" {
			return p.parseTypeDef()
		}
		switch p.tok {
		case tokLParen:
			return p.parseCall(name)
		case tokLBrace, tokLBrack:
			return p.parseStruct(name)
		case tokEq:
			return p.parseFlags(name)
		default:
			p.expect(tokLParen, tokLBrace, tokLBrack, tokEq)
		}
	case tokIllegal:
		// Scanner has already producer an error for this one.
		panic(errSkipLine)
	default:
		p.expect(tokComment, tokDefine, tokInclude, tokResource, tokIdent)
	}
	panic("not reachable")
}

func (p *parser) next() {
	p.tok, p.lit, p.pos = p.s.Scan()
}

func (p *parser) consume(tok token) {
	p.expect(tok)
	p.next()
}

func (p *parser) tryConsume(tok token) bool {
	if p.tok != tok {
		return false
	}
	p.next()
	return true
}

func (p *parser) expect(tokens ...token) {
	for _, tok := range tokens {
		if p.tok == tok {
			return
		}
	}
	var str []string
	for _, tok := range tokens {
		str = append(str, tok.String())
	}
	p.s.Error(p.pos, fmt.Sprintf("unexpected %v, expecting %v", p.tok, strings.Join(str, ", ")))
	panic(errSkipLine)
}

func (p *parser) parseComment() *Comment {
	c := &Comment{
		Pos:  p.pos,
		Text: p.lit,
	}
	p.consume(tokComment)
	return c
}

func (p *parser) parseDefine() *Define {
	pos0 := p.pos
	p.consume(tokDefine)
	name := p.parseIdent()
	p.expect(tokInt, tokIdent, tokCExpr)
	var val *Int
	if p.tok == tokCExpr {
		val = p.parseCExpr()
	} else {
		val = p.parseInt()
	}
	return &Define{
		Pos:   pos0,
		Name:  name,
		Value: val,
	}
}

func (p *parser) parseInclude() *Include {
	pos0 := p.pos
	p.consume(tokInclude)
	return &Include{
		Pos:  pos0,
		File: p.parseString(),
	}
}

func (p *parser) parseIncdir() *Incdir {
	pos0 := p.pos
	p.consume(tokIncdir)
	return &Incdir{
		Pos: pos0,
		Dir: p.parseString(),
	}
}

func (p *parser) parseResource() *Resource {
	pos0 := p.pos
	p.consume(tokResource)
	name := p.parseIdent()
	p.consume(tokLBrack)
	base := p.parseType()
	p.consume(tokRBrack)
	var values []*Int
	if p.tryConsume(tokColon) {
		values = append(values, p.parseInt())
		for p.tryConsume(tokComma) {
			values = append(values, p.parseInt())
		}
	}
	return &Resource{
		Pos:    pos0,
		Name:   name,
		Base:   base,
		Values: values,
	}
}

func (p *parser) parseTypeDef() *TypeDef {
	pos0 := p.pos
	name := p.parseIdent()
	var typ *Type
	var str *Struct
	var args []*Ident
	p.expect(tokLBrack, tokIdent)
	if p.tryConsume(tokLBrack) {
		args = append(args, p.parseIdent())
		for p.tryConsume(tokComma) {
			args = append(args, p.parseIdent())
		}
		p.consume(tokRBrack)
		if p.tok == tokLBrace || p.tok == tokLBrack {
			emptyName := &Ident{
				Pos:  pos0,
				Name: "",
			}
			str = p.parseStruct(emptyName)
		} else {
			typ = p.parseType()
		}
	} else {
		typ = p.parseType()
	}
	return &TypeDef{
		Pos:    pos0,
		Name:   name,
		Args:   args,
		Type:   typ,
		Struct: str,
	}
}

func (p *parser) parseCall(name *Ident) *Call {
	c := &Call{
		Pos:      name.Pos,
		Name:     name,
		CallName: callName(name.Name),
	}
	p.consume(tokLParen)
	for p.tok != tokRParen {
		c.Args = append(c.Args, p.parseField())
		p.expect(tokComma, tokRParen)
		p.tryConsume(tokComma)
	}
	p.consume(tokRParen)
	if p.tok != tokNewLine {
		c.Ret = p.parseType()
	}
	return c
}

func callName(s string) string {
	pos := strings.IndexByte(s, '$')
	if pos == -1 {
		return s
	}
	return s[:pos]
}

func (p *parser) parseFlags(name *Ident) Node {
	p.consume(tokEq)
	switch p.tok {
	case tokInt, tokIdent:
		return p.parseIntFlags(name)
	case tokString:
		return p.parseStrFlags(name)
	default:
		p.expect(tokInt, tokIdent, tokString)
		return nil
	}
}

func (p *parser) parseIntFlags(name *Ident) *IntFlags {
	values := []*Int{p.parseInt()}
	for p.tryConsume(tokComma) {
		values = append(values, p.parseInt())
	}
	return &IntFlags{
		Pos:    name.Pos,
		Name:   name,
		Values: values,
	}
}

func (p *parser) parseStrFlags(name *Ident) *StrFlags {
	values := []*String{p.parseString()}
	for p.tryConsume(tokComma) {
		values = append(values, p.parseString())
	}
	return &StrFlags{
		Pos:    name.Pos,
		Name:   name,
		Values: values,
	}
}

func (p *parser) parseStruct(name *Ident) *Struct {
	str := &Struct{
		Pos:  name.Pos,
		Name: name,
	}
	closing := tokRBrace
	if p.tok == tokLBrack {
		str.IsUnion = true
		closing = tokRBrack
	}
	p.next()
	p.consume(tokNewLine)
	for {
		newBlock := false
		for p.tok == tokNewLine {
			newBlock = true
			p.next()
		}
		comments := p.parseCommentBlock()
		if p.tryConsume(closing) {
			str.Comments = comments
			break
		}
		fld := p.parseField()
		fld.NewBlock = newBlock
		fld.Comments = comments
		str.Fields = append(str.Fields, fld)
		p.consume(tokNewLine)
	}
	if p.tryConsume(tokLBrack) {
		str.Attrs = append(str.Attrs, p.parseType())
		for p.tryConsume(tokComma) {
			str.Attrs = append(str.Attrs, p.parseType())
		}
		p.consume(tokRBrack)
	}
	return str
}

func (p *parser) parseCommentBlock() []*Comment {
	var comments []*Comment
	for p.tok == tokComment {
		comments = append(comments, p.parseComment())
		p.consume(tokNewLine)
		for p.tryConsume(tokNewLine) {
		}
	}
	return comments
}

func (p *parser) parseField() *Field {
	name := p.parseIdent()
	return &Field{
		Pos:  name.Pos,
		Name: name,
		Type: p.parseType(),
	}
}

func (p *parser) parseType() *Type {
	arg := &Type{
		Pos: p.pos,
	}
	allowColon := false
	switch p.tok {
	case tokInt:
		allowColon = true
		arg.Value, arg.ValueFmt = p.parseIntValue()
	case tokIdent:
		allowColon = true
		arg.Ident = p.lit
	case tokString:
		arg.String = p.lit
		arg.HasString = true
	default:
		p.expect(tokInt, tokIdent, tokString)
	}
	p.next()
	if allowColon {
		for p.tryConsume(tokColon) {
			col := &Type{
				Pos: p.pos,
			}
			switch p.tok {
			case tokInt:
				col.Value, col.ValueFmt = p.parseIntValue()
			case tokIdent:
				col.Ident = p.lit
			default:
				p.expect(tokInt, tokIdent)
			}
			arg.Colon = append(arg.Colon, col)
			p.next()
		}
	}
	arg.Args = p.parseTypeList()
	return arg
}

func (p *parser) parseTypeList() []*Type {
	var args []*Type
	if p.tryConsume(tokLBrack) {
		args = append(args, p.parseType())
		for p.tryConsume(tokComma) {
			args = append(args, p.parseType())
		}
		p.consume(tokRBrack)
	}
	return args
}

func (p *parser) parseIdent() *Ident {
	p.expect(tokIdent)
	ident := &Ident{
		Pos:  p.pos,
		Name: p.lit,
	}
	p.next()
	return ident
}

func (p *parser) parseString() *String {
	p.expect(tokString)
	str := &String{
		Pos:   p.pos,
		Value: p.lit,
	}
	p.next()
	return str
}

func (p *parser) parseInt() *Int {
	i := &Int{
		Pos: p.pos,
	}
	switch p.tok {
	case tokInt:
		i.Value, i.ValueFmt = p.parseIntValue()
	case tokIdent:
		i.Ident = p.lit
	default:
		p.expect(tokInt, tokIdent)
	}
	p.next()
	return i
}

func (p *parser) parseIntValue() (uint64, IntFmt) {
	if p.lit[0] == '\'' {
		return uint64(p.lit[1]), IntFmtChar
	}
	if v, err := strconv.ParseUint(p.lit, 10, 64); err == nil {
		return v, IntFmtDec
	}
	if v, err := strconv.ParseInt(p.lit, 10, 64); err == nil {
		return uint64(v), IntFmtNeg
	}
	if len(p.lit) > 2 && p.lit[0] == '0' && p.lit[1] == 'x' {
		if v, err := strconv.ParseUint(p.lit[2:], 16, 64); err == nil {
			return v, IntFmtHex
		}
	}
	panic(fmt.Sprintf("scanner returned bad integer %q", p.lit))
}

func (p *parser) parseCExpr() *Int {
	i := &Int{
		Pos:   p.pos,
		CExpr: p.lit,
	}
	p.consume(tokCExpr)
	return i
}
