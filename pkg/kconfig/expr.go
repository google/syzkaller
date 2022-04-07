// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
)

// expr represents an arbitrary kconfig expression used in "depends on", "visible if", "if", etc.
// Currently we can only extract dependent symbols from expressions.
type expr interface {
	String() string
	collectDeps(map[string]bool)
}

type exprShell struct {
	cmd string
}

func (ex *exprShell) String() string {
	return "$" + ex.cmd
}

func (ex *exprShell) collectDeps(deps map[string]bool) {
}

type exprNot struct {
	ex expr
}

func (ex *exprNot) String() string {
	return fmt.Sprintf("!(%v)", ex.ex)
}

func (ex *exprNot) collectDeps(deps map[string]bool) {
}

type exprIdent struct {
	name string
}

func (ex *exprIdent) String() string {
	return ex.name
}

func (ex *exprIdent) collectDeps(deps map[string]bool) {
	deps[ex.name] = true
}

type exprString struct {
	val string
}

func (ex *exprString) String() string {
	return fmt.Sprintf("%q", ex.val)
}

func (ex *exprString) collectDeps(deps map[string]bool) {
}

type exprBin struct {
	op  binOp
	lex expr
	rex expr
}

type binOp int

const (
	opNop binOp = iota
	opAnd
	opOr
	opEq
	opNe
	opLt
	opLe
	opGt
	opGe
)

func (op binOp) String() string {
	switch op {
	case opAnd:
		return "&&"
	case opOr:
		return "||"
	case opEq:
		return "="
	case opNe:
		return "!="
	case opLt:
		return "<"
	case opLe:
		return "<="
	case opGt:
		return ">"
	case opGe:
		return ">="
	default:
		return fmt.Sprintf("???(%v)", int(op))
	}
}

func (ex *exprBin) String() string {
	return fmt.Sprintf("(%v %v %v)", ex.lex, ex.op, ex.rex)
}

func (ex *exprBin) collectDeps(deps map[string]bool) {
	ex.lex.collectDeps(deps)
	ex.rex.collectDeps(deps)
}

func exprAnd(lex, rex expr) expr {
	if lex == nil {
		return rex
	}
	if rex == nil {
		return lex
	}
	return &exprBin{
		op:  opAnd,
		lex: lex,
		rex: rex,
	}
}

// Recursive-descent parsing with strict precedence levels.
// See kconfig docs for reference:
// https://www.kernel.org/doc/html/latest/kbuild/kconfig-language.html#menu-dependencies
// The doc claims that all operators have different precedence levels,
// e.g. '<' has higher precedence than '>' rather than being left-associative with the same precedence.
// This is somewhat strange semantics and here it is implemented as simply being left-associative.
// For now it does not matter since we do not evaluate expressions.
func (p *parser) parseExpr() expr {
	ex := p.parseExprAnd()
	for p.TryConsume("||") {
		ex = &exprBin{
			op:  opOr,
			lex: ex,
			rex: p.parseExprAnd(),
		}
	}
	return ex
}

func (p *parser) parseExprAnd() expr {
	ex := p.parseExprCmp()
	for p.TryConsume("&&") {
		ex = &exprBin{
			op:  opAnd,
			lex: ex,
			rex: p.parseExprCmp(),
		}
	}
	return ex
}

func (p *parser) parseExprCmp() expr {
	ex := p.parseExprTerm()
	for {
		op := opNop
		switch {
		case p.TryConsume("="):
			op = opEq
		case p.TryConsume("!="):
			op = opNe
		case p.TryConsume("<="):
			op = opLe
		case p.TryConsume(">="):
			op = opGe
		case p.TryConsume("<"):
			op = opLt
		case p.TryConsume(">"):
			op = opGt
		}
		if op == opNop {
			break
		}
		ex = &exprBin{
			op:  op,
			lex: ex,
			rex: p.parseExprTerm(),
		}
	}
	return ex
}

func (p *parser) parseExprTerm() expr {
	if p.TryConsume("$") {
		return &exprShell{
			cmd: p.Shell(),
		}
	}
	if str, ok := p.TryQuotedString(); ok {
		return &exprString{
			val: str,
		}
	}
	if p.TryConsume("!") {
		return &exprNot{
			ex: p.parseExprTerm(),
		}
	}
	if p.TryConsume("(") {
		ex := p.parseExpr()
		p.MustConsume(")")
		return ex
	}
	return &exprIdent{
		name: p.Ident(),
	}
}
