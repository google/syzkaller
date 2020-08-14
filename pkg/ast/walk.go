// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

// Walk calls callback cb for every top-level node in description.
// Note: it's not recursive. Use Recursive/PostRecursive helpers for recursive walk.
func (desc *Description) Walk(cb func(Node)) {
	for _, n := range desc.Nodes {
		cb(n)
	}
}

func Recursive(cb func(Node)) func(Node) {
	var rec func(Node)
	rec = func(n Node) {
		cb(n)
		n.walk(rec)
	}
	return rec
}

func PostRecursive(cb func(Node)) func(Node) {
	var rec func(Node)
	rec = func(n Node) {
		n.walk(rec)
		cb(n)
	}
	return rec
}

func (n *NewLine) walk(cb func(Node)) {}
func (n *Comment) walk(cb func(Node)) {}
func (n *Ident) walk(cb func(Node))   {}
func (n *String) walk(cb func(Node))  {}
func (n *Int) walk(cb func(Node))     {}

func (n *Include) walk(cb func(Node)) {
	cb(n.File)
}

func (n *Incdir) walk(cb func(Node)) {
	cb(n.Dir)
}

func (n *Define) walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Value)
}

func (n *Resource) walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Base)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *TypeDef) walk(cb func(Node)) {
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

func (n *Call) walk(cb func(Node)) {
	cb(n.Name)
	for _, f := range n.Args {
		cb(f)
	}
	if n.Ret != nil {
		cb(n.Ret)
	}
	for _, a := range n.Attrs {
		cb(a)
	}
}

func (n *Struct) walk(cb func(Node)) {
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

func (n *IntFlags) walk(cb func(Node)) {
	cb(n.Name)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *StrFlags) walk(cb func(Node)) {
	cb(n.Name)
	for _, v := range n.Values {
		cb(v)
	}
}

func (n *Type) walk(cb func(Node)) {
	for _, t := range n.Args {
		cb(t)
	}
}

func (n *Field) walk(cb func(Node)) {
	cb(n.Name)
	cb(n.Type)
	for _, a := range n.Attrs {
		cb(a)
	}
	for _, c := range n.Comments {
		cb(c)
	}
}
