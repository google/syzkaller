// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ast parses and formats sys files.
package ast

// Pos represents source info for AST nodes.
type Pos struct {
	File string
	Off  int // byte offset, starting at 0
	Line int // line number, starting at 1
	Col  int // column number, starting at 1 (byte count)
}

// Top-level AST nodes:

type NewLine struct {
	Pos Pos
}

type Comment struct {
	Pos  Pos
	Text string
}

type Include struct {
	Pos  Pos
	File *String
}

type Incdir struct {
	Pos Pos
	Dir *String
}

type Define struct {
	Pos   Pos
	Name  *Ident
	Value *Int
}

type Resource struct {
	Pos    Pos
	Name   *Ident
	Base   *Ident
	Values []*Int
}

type Call struct {
	Pos      Pos
	Name     *Ident
	CallName string
	Args     []*Field
	Ret      *Type
}

type Struct struct {
	Pos      Pos
	Name     *Ident
	Fields   []*Field
	Attrs    []*Ident
	Comments []*Comment
	IsUnion  bool
}

type IntFlags struct {
	Pos    Pos
	Name   *Ident
	Values []*Int
}

type StrFlags struct {
	Pos    Pos
	Name   *Ident
	Values []*String
}

// Not top-level AST nodes:

type Ident struct {
	Pos  Pos
	Name string
}

type String struct {
	Pos   Pos
	Value string
}

type Int struct {
	Pos Pos
	// Only one of Value, Ident, CExpr is filled.
	Value    uint64
	ValueHex bool // says if value was in hex (for formatting)
	Ident    string
	CExpr    string
}

type Type struct {
	Pos Pos
	// Only one of Value, Ident, String is filled.
	Value    uint64
	ValueHex bool
	Ident    string
	String   string
	// Part after COLON (for ranges and bitfields).
	Value2    uint64
	Value2Hex bool
	Ident2    string
	Args      []*Type
}

type Field struct {
	Pos      Pos
	Name     *Ident
	Type     *Type
	NewBlock bool // separated from previous fields by a new line
	Comments []*Comment
}
