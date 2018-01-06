// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

func Clone(desc *Description) *Description {
	desc1 := &Description{}
	for _, n := range desc.Nodes {
		desc1.Nodes = append(desc1.Nodes, n.Clone(Pos{}))
	}
	return desc1
}

func selectPos(newPos, oldPos Pos) Pos {
	if newPos.File != "" || newPos.Off != 0 || newPos.Line != 0 || newPos.Col != 0 {
		return newPos
	}
	return oldPos
}

func (n *NewLine) Clone(newPos Pos) Node {
	return &NewLine{
		Pos: selectPos(newPos, n.Pos),
	}
}

func (n *Comment) Clone(newPos Pos) Node {
	return &Comment{
		Pos:  selectPos(newPos, n.Pos),
		Text: n.Text,
	}
}

func (n *Include) Clone(newPos Pos) Node {
	return &Include{
		Pos:  selectPos(newPos, n.Pos),
		File: n.File.Clone(newPos).(*String),
	}
}

func (n *Incdir) Clone(newPos Pos) Node {
	return &Incdir{
		Pos: selectPos(newPos, n.Pos),
		Dir: n.Dir.Clone(newPos).(*String),
	}
}

func (n *Define) Clone(newPos Pos) Node {
	return &Define{
		Pos:   selectPos(newPos, n.Pos),
		Name:  n.Name.Clone(newPos).(*Ident),
		Value: n.Value.Clone(newPos).(*Int),
	}
}

func (n *Resource) Clone(newPos Pos) Node {
	var values []*Int
	for _, v := range n.Values {
		values = append(values, v.Clone(newPos).(*Int))
	}
	return &Resource{
		Pos:    selectPos(newPos, n.Pos),
		Name:   n.Name.Clone(newPos).(*Ident),
		Base:   n.Base.Clone(newPos).(*Type),
		Values: values,
	}
}

func (n *TypeDef) Clone(newPos Pos) Node {
	return &TypeDef{
		Pos:  selectPos(newPos, n.Pos),
		Name: n.Name.Clone(newPos).(*Ident),
		Type: n.Type.Clone(newPos).(*Type),
	}
}

func (n *Call) Clone(newPos Pos) Node {
	var args []*Field
	for _, a := range n.Args {
		args = append(args, a.Clone(newPos).(*Field))
	}
	var ret *Type
	if n.Ret != nil {
		ret = n.Ret.Clone(newPos).(*Type)
	}
	return &Call{
		Pos:      selectPos(newPos, n.Pos),
		Name:     n.Name.Clone(newPos).(*Ident),
		CallName: n.CallName,
		NR:       n.NR,
		Args:     args,
		Ret:      ret,
	}
}

func (n *Struct) Clone(newPos Pos) Node {
	var fields []*Field
	for _, f := range n.Fields {
		fields = append(fields, f.Clone(newPos).(*Field))
	}
	var attrs []*Ident
	for _, a := range n.Attrs {
		attrs = append(attrs, a.Clone(newPos).(*Ident))
	}
	var comments []*Comment
	for _, c := range n.Comments {
		comments = append(comments, c.Clone(newPos).(*Comment))
	}
	return &Struct{
		Pos:      selectPos(newPos, n.Pos),
		Name:     n.Name.Clone(newPos).(*Ident),
		Fields:   fields,
		Attrs:    attrs,
		Comments: comments,
		IsUnion:  n.IsUnion,
	}
}

func (n *IntFlags) Clone(newPos Pos) Node {
	var values []*Int
	for _, v := range n.Values {
		values = append(values, v.Clone(newPos).(*Int))
	}
	return &IntFlags{
		Pos:    selectPos(newPos, n.Pos),
		Name:   n.Name.Clone(newPos).(*Ident),
		Values: values,
	}
}

func (n *StrFlags) Clone(newPos Pos) Node {
	var values []*String
	for _, v := range n.Values {
		values = append(values, v.Clone(newPos).(*String))
	}
	return &StrFlags{
		Pos:    selectPos(newPos, n.Pos),
		Name:   n.Name.Clone(newPos).(*Ident),
		Values: values,
	}
}

func (n *Ident) Clone(newPos Pos) Node {
	return &Ident{
		Pos:  selectPos(newPos, n.Pos),
		Name: n.Name,
	}
}

func (n *String) Clone(newPos Pos) Node {
	return &String{
		Pos:   selectPos(newPos, n.Pos),
		Value: n.Value,
	}
}

func (n *Int) Clone(newPos Pos) Node {
	return &Int{
		Pos:      selectPos(newPos, n.Pos),
		Value:    n.Value,
		ValueHex: n.ValueHex,
		Ident:    n.Ident,
		CExpr:    n.CExpr,
	}
}

func (n *Type) Clone(newPos Pos) Node {
	var args []*Type
	for _, a := range n.Args {
		args = append(args, a.Clone(newPos).(*Type))
	}
	return &Type{
		Pos:       selectPos(newPos, n.Pos),
		Value:     n.Value,
		ValueHex:  n.ValueHex,
		Ident:     n.Ident,
		String:    n.String,
		HasColon:  n.HasColon,
		Pos2:      selectPos(newPos, n.Pos2),
		Value2:    n.Value2,
		Value2Hex: n.Value2Hex,
		Ident2:    n.Ident2,
		Args:      args,
	}
}

func (n *Field) Clone(newPos Pos) Node {
	var comments []*Comment
	for _, c := range n.Comments {
		comments = append(comments, c.Clone(newPos).(*Comment))
	}
	return &Field{
		Pos:      selectPos(newPos, n.Pos),
		Name:     n.Name.Clone(newPos).(*Ident),
		Type:     n.Type.Clone(newPos).(*Type),
		NewBlock: n.NewBlock,
		Comments: comments,
	}
}
