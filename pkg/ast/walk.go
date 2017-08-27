// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"fmt"
)

// Walk calls callback cb for every node in AST.
func Walk(desc *Description, cb func(n Node)) {
	for _, n := range desc.Nodes {
		WalkNode(n, cb)
	}
}

func WalkNode(n0 Node, cb func(n Node)) {
	cb(n0)
	switch n := n0.(type) {
	case *NewLine:
	case *Comment:
	case *Include:
		WalkNode(n.File, cb)
	case *Incdir:
		WalkNode(n.Dir, cb)
	case *Define:
		WalkNode(n.Name, cb)
		WalkNode(n.Value, cb)
	case *Resource:
		WalkNode(n.Name, cb)
		WalkNode(n.Base, cb)
		for _, v := range n.Values {
			WalkNode(v, cb)
		}
	case *Call:
		WalkNode(n.Name, cb)
		for _, f := range n.Args {
			WalkNode(f, cb)
		}
		if n.Ret != nil {
			WalkNode(n.Ret, cb)
		}
	case *Struct:
		WalkNode(n.Name, cb)
		for _, f := range n.Fields {
			WalkNode(f, cb)
		}
		for _, a := range n.Attrs {
			WalkNode(a, cb)
		}
		for _, c := range n.Comments {
			WalkNode(c, cb)
		}
	case *IntFlags:
		WalkNode(n.Name, cb)
		for _, v := range n.Values {
			WalkNode(v, cb)
		}
	case *StrFlags:
		WalkNode(n.Name, cb)
		for _, v := range n.Values {
			WalkNode(v, cb)
		}
	case *Ident:
	case *String:
	case *Int:
	case *Type:
		for _, t := range n.Args {
			WalkNode(t, cb)
		}
	case *Field:
		WalkNode(n.Name, cb)
		WalkNode(n.Type, cb)
		for _, c := range n.Comments {
			WalkNode(c, cb)
		}
	default:
		panic(fmt.Sprintf("unknown AST node: %#v", n))
	}
}
