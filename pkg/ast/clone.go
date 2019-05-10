// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

func (desc *Description) Clone() *Description {
	desc1 := &Description{}
	for _, n := range desc.Nodes {
		desc1.Nodes = append(desc1.Nodes, n.Clone())
	}
	return desc1
}

func (n *NewLine) Clone() Node {
	return &NewLine{
		Pos: n.Pos,
	}
}

func (n *Comment) Clone() Node {
	return &Comment{
		Pos:  n.Pos,
		Text: n.Text,
	}
}

func (n *Include) Clone() Node {
	return &Include{
		Pos:  n.Pos,
		File: n.File.Clone().(*String),
	}
}

func (n *Incdir) Clone() Node {
	return &Incdir{
		Pos: n.Pos,
		Dir: n.Dir.Clone().(*String),
	}
}

func (n *Define) Clone() Node {
	return &Define{
		Pos:   n.Pos,
		Name:  n.Name.Clone().(*Ident),
		Value: n.Value.Clone().(*Int),
	}
}

func (n *Resource) Clone() Node {
	return &Resource{
		Pos:    n.Pos,
		Name:   n.Name.Clone().(*Ident),
		Base:   n.Base.Clone().(*Type),
		Values: cloneInts(n.Values),
	}
}

func (n *TypeDef) Clone() Node {
	var args []*Ident
	for _, v := range n.Args {
		args = append(args, v.Clone().(*Ident))
	}
	var typ *Type
	if n.Type != nil {
		typ = n.Type.Clone().(*Type)
	}
	var str *Struct
	if n.Struct != nil {
		str = n.Struct.Clone().(*Struct)
	}
	return &TypeDef{
		Pos:    n.Pos,
		Name:   n.Name.Clone().(*Ident),
		Args:   args,
		Type:   typ,
		Struct: str,
	}
}

func (n *Call) Clone() Node {
	var ret *Type
	if n.Ret != nil {
		ret = n.Ret.Clone().(*Type)
	}
	return &Call{
		Pos:      n.Pos,
		Name:     n.Name.Clone().(*Ident),
		CallName: n.CallName,
		NR:       n.NR,
		Args:     cloneFields(n.Args),
		Ret:      ret,
	}
}

func (n *Struct) Clone() Node {
	return &Struct{
		Pos:      n.Pos,
		Name:     n.Name.Clone().(*Ident),
		Fields:   cloneFields(n.Fields),
		Attrs:    cloneTypes(n.Attrs),
		Comments: cloneComments(n.Comments),
		IsUnion:  n.IsUnion,
	}
}

func (n *IntFlags) Clone() Node {
	return &IntFlags{
		Pos:    n.Pos,
		Name:   n.Name.Clone().(*Ident),
		Values: cloneInts(n.Values),
	}
}

func (n *StrFlags) Clone() Node {
	var values []*String
	for _, v := range n.Values {
		values = append(values, v.Clone().(*String))
	}
	return &StrFlags{
		Pos:    n.Pos,
		Name:   n.Name.Clone().(*Ident),
		Values: values,
	}
}

func (n *Ident) Clone() Node {
	return &Ident{
		Pos:  n.Pos,
		Name: n.Name,
	}
}

func (n *String) Clone() Node {
	return &String{
		Pos:   n.Pos,
		Value: n.Value,
	}
}

func (n *Int) Clone() Node {
	return &Int{
		Pos:      n.Pos,
		Value:    n.Value,
		ValueFmt: n.ValueFmt,
		Ident:    n.Ident,
		CExpr:    n.CExpr,
	}
}

func (n *Type) Clone() Node {
	return &Type{
		Pos:       n.Pos,
		Value:     n.Value,
		ValueFmt:  n.ValueFmt,
		Ident:     n.Ident,
		String:    n.String,
		HasString: n.HasString,
		Colon:     cloneTypes(n.Colon),
		Args:      cloneTypes(n.Args),
	}
}

func (n *Field) Clone() Node {
	return &Field{
		Pos:      n.Pos,
		Name:     n.Name.Clone().(*Ident),
		Type:     n.Type.Clone().(*Type),
		NewBlock: n.NewBlock,
		Comments: cloneComments(n.Comments),
	}
}

func cloneFields(list []*Field) (res []*Field) {
	for _, n := range list {
		res = append(res, n.Clone().(*Field))
	}
	return
}

func cloneInts(list []*Int) (res []*Int) {
	for _, n := range list {
		res = append(res, n.Clone().(*Int))
	}
	return
}

func cloneTypes(list []*Type) (res []*Type) {
	for _, n := range list {
		res = append(res, n.Clone().(*Type))
	}
	return
}

func cloneComments(list []*Comment) (res []*Comment) {
	for _, n := range list {
		res = append(res, n.Clone().(*Comment))
	}
	return
}
