// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"fmt"
)

// Walk calls callback cb for every node in AST.
func Walk(top []interface{}, cb func(n interface{})) {
	for _, decl := range top {
		walkNode(decl, cb)
	}
}

func walkNode(n0 interface{}, cb func(n interface{})) {
	switch n := n0.(type) {
	case *NewLine:
		cb(n)
	case *Comment:
		cb(n)
	case *Include:
		cb(n)
		walkNode(n.File, cb)
	case *Incdir:
		cb(n)
		walkNode(n.Dir, cb)
	case *Define:
		cb(n)
		walkNode(n.Name, cb)
		walkNode(n.Value, cb)
	case *Resource:
		cb(n)
		walkNode(n.Name, cb)
		walkNode(n.Base, cb)
		for _, v := range n.Values {
			walkNode(v, cb)
		}
	case *Call:
		cb(n)
		walkNode(n.Name, cb)
		for _, f := range n.Args {
			walkNode(f, cb)
		}
		if n.Ret != nil {
			walkNode(n.Ret, cb)
		}
	case *Struct:
		cb(n)
		walkNode(n.Name, cb)
		for _, f := range n.Fields {
			walkNode(f, cb)
		}
		for _, a := range n.Attrs {
			walkNode(a, cb)
		}
		for _, c := range n.Comments {
			walkNode(c, cb)
		}
	case *IntFlags:
		cb(n)
		walkNode(n.Name, cb)
		for _, v := range n.Values {
			walkNode(v, cb)
		}
	case *StrFlags:
		cb(n)
		walkNode(n.Name, cb)
		for _, v := range n.Values {
			walkNode(v, cb)
		}
	case *Ident:
		cb(n)
	case *String:
		cb(n)
	case *Int:
		cb(n)
	case *Type:
		cb(n)
		for _, t := range n.Args {
			walkNode(t, cb)
		}
	case *Field:
		cb(n)
		walkNode(n.Name, cb)
		walkNode(n.Type, cb)
		for _, c := range n.Comments {
			walkNode(c, cb)
		}
	default:
		panic(fmt.Sprintf("unknown AST node: %#v", n))
	}
}
