// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"fmt"
)

func Clone(desc *Description) *Description {
	desc1 := &Description{}
	for _, n := range desc.Nodes {
		c, ok := n.(cloner)
		if !ok {
			panic(fmt.Sprintf("unknown top level decl: %#v", n))
		}
		desc1.Nodes = append(desc1.Nodes, c.clone())
	}
	return desc1
}

type cloner interface {
	clone() Node
}

func (n *NewLine) clone() Node {
	return &NewLine{
		Pos: n.Pos,
	}
}

func (n *Comment) clone() Node {
	return &Comment{
		Pos:  n.Pos,
		Text: n.Text,
	}
}

func (n *Include) clone() Node {
	return &Include{
		Pos:  n.Pos,
		File: n.File.clone(),
	}
}

func (n *Incdir) clone() Node {
	return &Incdir{
		Pos: n.Pos,
		Dir: n.Dir.clone(),
	}
}

func (n *Define) clone() Node {
	return &Define{
		Pos:   n.Pos,
		Name:  n.Name.clone(),
		Value: n.Value.clone(),
	}
}

func (n *Resource) clone() Node {
	var values []*Int
	for _, v := range n.Values {
		values = append(values, v.clone())
	}
	return &Resource{
		Pos:    n.Pos,
		Name:   n.Name.clone(),
		Base:   n.Base.clone(),
		Values: values,
	}
}

func (n *Call) clone() Node {
	var args []*Field
	for _, a := range n.Args {
		args = append(args, a.clone())
	}
	var ret *Type
	if n.Ret != nil {
		ret = n.Ret.clone()
	}
	return &Call{
		Pos:      n.Pos,
		Name:     n.Name.clone(),
		CallName: n.CallName,
		NR:       n.NR,
		Args:     args,
		Ret:      ret,
	}
}

func (n *Struct) clone() Node {
	var fields []*Field
	for _, f := range n.Fields {
		fields = append(fields, f.clone())
	}
	var attrs []*Ident
	for _, a := range n.Attrs {
		attrs = append(attrs, a.clone())
	}
	var comments []*Comment
	for _, c := range n.Comments {
		comments = append(comments, c.clone().(*Comment))
	}
	return &Struct{
		Pos:      n.Pos,
		Name:     n.Name.clone(),
		Fields:   fields,
		Attrs:    attrs,
		Comments: comments,
		IsUnion:  n.IsUnion,
	}
}

func (n *IntFlags) clone() Node {
	var values []*Int
	for _, v := range n.Values {
		values = append(values, v.clone())
	}
	return &IntFlags{
		Pos:    n.Pos,
		Name:   n.Name.clone(),
		Values: values,
	}
}

func (n *StrFlags) clone() Node {
	var values []*String
	for _, v := range n.Values {
		values = append(values, v.clone())
	}
	return &StrFlags{
		Pos:    n.Pos,
		Name:   n.Name.clone(),
		Values: values,
	}
}

func (n *Ident) clone() *Ident {
	return &Ident{
		Pos:  n.Pos,
		Name: n.Name,
	}
}

func (n *String) clone() *String {
	return &String{
		Pos:   n.Pos,
		Value: n.Value,
	}
}

func (n *Int) clone() *Int {
	return &Int{
		Pos:      n.Pos,
		Value:    n.Value,
		ValueHex: n.ValueHex,
		Ident:    n.Ident,
		CExpr:    n.CExpr,
	}
}

func (n *Type) clone() *Type {
	var args []*Type
	for _, a := range n.Args {
		args = append(args, a.clone())
	}
	return &Type{
		Pos:       n.Pos,
		Value:     n.Value,
		ValueHex:  n.ValueHex,
		Ident:     n.Ident,
		String:    n.String,
		HasColon:  n.HasColon,
		Pos2:      n.Pos2,
		Value2:    n.Value2,
		Value2Hex: n.Value2Hex,
		Ident2:    n.Ident2,
		Args:      args,
	}
}

func (n *Field) clone() *Field {
	var comments []*Comment
	for _, c := range n.Comments {
		comments = append(comments, c.clone().(*Comment))
	}
	return &Field{
		Pos:      n.Pos,
		Name:     n.Name.clone(),
		Type:     n.Type.clone(),
		NewBlock: n.NewBlock,
		Comments: comments,
	}
}
