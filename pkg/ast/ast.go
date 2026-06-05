// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ast parses and formats sys files.
package ast

// Description contains top-level nodes of a parsed sys description.
type Description struct {
	Nodes []Node
}

// Node is AST node interface.
type Node interface {
	Info() (pos Pos, typ, name string)
	// Clone makes a deep copy of the node.
	Clone() Node
	// walk calls callback cb for all child nodes of this node.
	// Note: it's not recursive. Use Recursive helper for recursive walk.
	walk(cb func(Node))
}

type Flags[T FlagValue] interface {
	SetValues(values []T)
	GetValues() []T
	GetPos() Pos
}

type FlagValue interface {
	GetName() string
}

// Top-level AST nodes.
type NewLine struct {
	Pos Pos
}

type Comment struct {
	Pos  Pos
	Text string
}

type Meta struct {
	Pos   Pos
	Value *Type
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
	Base   *Type
	Values []*Int
}

type Call struct {
	Pos      Pos
	Name     *Ident
	CallName string
	NR       uint64
	Args     []*Field
	Ret      *Type
	Attrs    []*Type
}

type Struct struct {
	Pos      Pos
	Name     *Ident
	Fields   []*Field
	Attrs    []*Type
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

type TypeDef struct {
	Pos  Pos
	Name *Ident
	// Non-template type aliases have only Type filled.
	// Templates have Args and either Type or Struct filled.
	Args   []*Ident
	Type   *Type
	Struct *Struct
}

// Not top-level AST nodes.
type Ident struct {
	Pos  Pos
	Name string
}

type String struct {
	Pos   Pos
	Value string
	Fmt   StrFmt
}

func (n *StrFlags) SetValues(values []*String) {
	n.Values = values
}

func (n *StrFlags) GetValues() []*String {
	return n.Values
}

func (n *String) GetName() string {
	return n.Value
}

type IntFmt int

const (
	IntFmtDec IntFmt = iota
	IntFmtNeg
	IntFmtHex
	IntFmtChar
)

type StrFmt int

const (
	StrFmtRaw StrFmt = iota
	StrFmtHex
	StrFmtIdent
)

type Int struct {
	Pos Pos
	// Only one of Value, Ident, CExpr is filled.
	Value    uint64
	ValueFmt IntFmt
	Ident    string
	CExpr    string
}

func (n *IntFlags) SetValues(values []*Int) {
	n.Values = values
}

func (n *IntFlags) GetValues() []*Int {
	return n.Values
}

func (n *Int) GetName() string {
	return n.Ident
}

type Operator int

const (
	OperatorCompareEq = iota + 1
	OperatorCompareNeq
	OperatorBinaryAnd
	OperatorOr
)

type BinaryExpression struct {
	Pos      Pos
	Operator Operator
	Left     *Type
	Right    *Type
}

type Type struct {
	Pos Pos
	// Only one of Value, Ident, String, Expression is filled.
	Value      uint64
	ValueFmt   IntFmt
	Ident      string
	String     string
	StringFmt  StrFmt
	HasString  bool
	Expression *BinaryExpression
	// Parts after COLON (for ranges and bitfields).
	Colon []*Type
	// Sub-types in [].
	Args []*Type
}

type Field struct {
	Pos      Pos
	Name     *Ident
	Type     *Type
	Attrs    []*Type
	NewBlock bool // separated from previous fields by a new line
	Comments []*Comment
}

// Pos represents source info for AST nodes.
type Pos struct {
	File string
	Off  int // byte offset, starting at 0
	Line int // line number, starting at 1
	Col  int // column number, starting at 1 (byte count)
}

func (n *NewLine) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokNewLine], ""
}

func (n *Comment) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokComment], ""
}

func (n *Meta) Info() (Pos, string, string) {
	return n.Pos, "meta", n.Value.Ident
}

func (n *Include) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokInclude], n.File.Value
}

func (n *Incdir) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokInclude], ""
}

func (n *Define) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokDefine], n.Name.Name
}

func (n *Resource) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokResource], n.Name.Name
}

func (n *Call) Info() (Pos, string, string) {
	return n.Pos, "syscall", n.Name.Name
}

func (n *Struct) Info() (Pos, string, string) {
	typ := "struct"
	if n.IsUnion {
		typ = "union"
	}
	return n.Pos, typ, n.Name.Name
}

func (n *IntFlags) Info() (Pos, string, string) {
	return n.Pos, "flags", n.Name.Name
}

func (n *IntFlags) GetPos() Pos {
	return n.Pos
}

func (n *StrFlags) Info() (Pos, string, string) {
	return n.Pos, "string flags", n.Name.Name
}

func (n *StrFlags) GetPos() Pos {
	return n.Pos
}

func (n *TypeDef) Info() (Pos, string, string) {
	return n.Pos, "type", n.Name.Name
}

func (n *Ident) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokIdent], n.Name
}

func (n *String) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokString], ""
}

func (n *Int) Info() (Pos, string, string) {
	return n.Pos, tok2str[tokInt], ""
}

func (n *BinaryExpression) Info() (Pos, string, string) {
	return n.Pos, "binary-expression", ""
}

func (n *Type) Info() (Pos, string, string) {
	return n.Pos, "type-opt", n.Ident
}

func (n *Field) Info() (Pos, string, string) {
	return n.Pos, "arg/field", n.Name.Name
}
