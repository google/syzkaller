// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"fmt"
)

// Walk calls callback cb for every node in AST.
func Walk(desc *Description, cb func(n, parent Node)) {
	for _, n := range desc.Nodes {
		WalkNode(n, nil, cb)
	}
}

func WalkNode(n0, parent Node, cb func(n, parent Node)) {
	cb(n0, parent)
	switch n := n0.(type) {
	case *NewLine:
	case *Comment:
	case *Include:
		WalkNode(n.File, n, cb)
	case *Incdir:
		WalkNode(n.Dir, n, cb)
	case *Define:
		WalkNode(n.Name, n, cb)
		WalkNode(n.Value, n, cb)
	case *Resource:
		WalkNode(n.Name, n, cb)
		WalkNode(n.Base, n, cb)
		for _, v := range n.Values {
			WalkNode(v, n, cb)
		}
	case *Call:
		WalkNode(n.Name, n, cb)
		for _, f := range n.Args {
			WalkNode(f, n, cb)
		}
		if n.Ret != nil {
			WalkNode(n.Ret, n, cb)
		}
	case *Struct:
		WalkNode(n.Name, n, cb)
		for _, f := range n.Fields {
			WalkNode(f, n, cb)
		}
		for _, a := range n.Attrs {
			WalkNode(a, n, cb)
		}
		for _, c := range n.Comments {
			WalkNode(c, n, cb)
		}
	case *IntFlags:
		WalkNode(n.Name, n, cb)
		for _, v := range n.Values {
			WalkNode(v, n, cb)
		}
	case *StrFlags:
		WalkNode(n.Name, n, cb)
		for _, v := range n.Values {
			WalkNode(v, n, cb)
		}
	case *Ident:
	case *String:
	case *Int:
	case *Type:
		for _, t := range n.Args {
			WalkNode(t, n, cb)
		}
	case *Field:
		WalkNode(n.Name, n, cb)
		WalkNode(n.Type, n, cb)
		for _, c := range n.Comments {
			WalkNode(c, n, cb)
		}
	default:
		panic(fmt.Sprintf("unknown AST node: %#v", n))
	}
}
