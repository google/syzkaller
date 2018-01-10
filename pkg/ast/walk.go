// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

// Walk calls callback cb for every top-level node in description.
// Note: it's not recursive. Use Recursive helper for recursive walk.
func (desc *Description) Walk(cb func(Node)) {
	for _, n := range desc.Nodes {
		cb(n)
	}
}

func Recursive(cb func(Node)) func(Node) {
	var rec func(Node)
	rec = func(n Node) {
		cb(n)
		n.Walk(rec)
	}
	return rec
}

func (n *NewLine) Walk(cb func(Node)) {}
func (n *Comment) Walk(cb func(Node)) {}
func (n *Ident) Walk(cb func(Node))   {}
func (n *String) Walk(cb func(Node))  {}
func (n *Int) Walk(cb func(Node))     {}

func (n *Include) Walk(cb func(Node)) {
	cb(n.File)
}

func (n *Incdir) Walk(cb func(Node)) {
	cb(n.Dir)
}

func (n *Define) Walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Value)
}

func (n *Resource) Walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Base)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *TypeDef) Walk(cb func(Node)) {
	cb(n.Name)
	for _, a := range n.Args {
		cb(a)
	}
	if n.Type != nil {
		cb(n.Type)
	}
	if n.Struct != nil {
		cb(n.Struct)
	}
}

func (n *Call) Walk(cb func(Node)) {
	cb(n.Name)
	for _, f := range n.Args {
		cb(f)
	}
	if n.Ret != nil {
		cb(n.Ret)
	}
}

func (n *Struct) Walk(cb func(Node)) {
	cb(n.Name)
	for _, f := range n.Fields {
		cb(f)
	}
	for _, a := range n.Attrs {
		cb(a)
	}
	for _, c := range n.Comments {
		cb(c)
	}
}

func (n *IntFlags) Walk(cb func(Node)) {
	cb(n.Name)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *StrFlags) Walk(cb func(Node)) {
	cb(n.Name)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *Type) Walk(cb func(Node)) {
	for _, t := range n.Args {
		cb(t)
	}
}

func (n *Field) Walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Type)
	for _, c := range n.Comments {
		cb(c)
	}
}
