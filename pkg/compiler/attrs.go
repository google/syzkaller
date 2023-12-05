// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"reflect"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
)

type attrDescAttrType int

const (
	flagAttr attrDescAttrType = iota
	// TODO: Ultimately we want to replace intAttr with exprAttr.
	// This will facilitate const expressions in e.g. size[] or align[].
	intAttr
	exprAttr
)

type attrDesc struct {
	Name string
	// For now we assume attributes can have only 1 argument and it's either an
	// integer or an expression.
	Type attrDescAttrType
	// This function is not invoked for per-field attributes, only for whole
	// structs/unions.
	CheckConsts func(comp *compiler, parent ast.Node, attr *ast.Type)
}

var (
	attrPacked     = &attrDesc{Name: "packed"}
	attrVarlen     = &attrDesc{Name: "varlen"}
	attrSize       = &attrDesc{Name: "size", Type: intAttr}
	attrAlign      = &attrDesc{Name: "align", Type: intAttr}
	attrIn         = &attrDesc{Name: "in"}
	attrOut        = &attrDesc{Name: "out"}
	attrInOut      = &attrDesc{Name: "inout"}
	attrOutOverlay = &attrDesc{Name: "out_overlay"}
	attrIf         = &attrDesc{Name: "if", Type: exprAttr}

	structAttrs      = makeAttrs(attrPacked, attrSize, attrAlign)
	unionAttrs       = makeAttrs(attrVarlen, attrSize)
	structFieldAttrs = makeAttrs(attrIn, attrOut, attrInOut, attrOutOverlay, attrIf)
	unionFieldAttrs  = makeAttrs(attrIn, attrIf) // attrIn is safe.
	callAttrs        = make(map[string]*attrDesc)
)

func init() {
	initCallAttrs()

	attrSize.CheckConsts = func(comp *compiler, parent ast.Node, attr *ast.Type) {
		_, typ, name := parent.Info()
		if comp.structIsVarlen(name) {
			comp.error(attr.Pos, "varlen %v %v has size attribute", typ, name)
		}
		sz := attr.Args[0].Value
		if sz == 0 || sz > 1<<20 {
			comp.error(attr.Args[0].Pos, "size attribute has bad value %v"+
				", expect [1, 1<<20]", sz)
		}
	}
	attrAlign.CheckConsts = func(comp *compiler, parent ast.Node, attr *ast.Type) {
		_, _, name := parent.Info()
		a := attr.Args[0].Value
		if a&(a-1) != 0 || a == 0 || a > 1<<30 {
			comp.error(attr.Pos, "bad struct %v alignment %v (must be a sane power of 2)", name, a)
		}
	}
}

func initCallAttrs() {
	attrs := reflect.TypeOf(prog.SyscallAttrs{})
	for i := 0; i < attrs.NumField(); i++ {
		attr := attrs.Field(i)
		desc := &attrDesc{Name: attr.Name}
		switch attr.Type.Kind() {
		case reflect.Bool:
		case reflect.Uint64:
			desc.Type = intAttr
		default:
			panic("unsupported syscall attribute type")
		}
		callAttrs[prog.CppName(desc.Name)] = desc
	}
}

func structOrUnionAttrs(n *ast.Struct) map[string]*attrDesc {
	if n.IsUnion {
		return unionAttrs
	}
	return structAttrs
}

func structOrUnionFieldAttrs(n *ast.Struct) map[string]*attrDesc {
	if n.IsUnion {
		return unionFieldAttrs
	}
	return structFieldAttrs
}

func makeAttrs(attrs ...*attrDesc) map[string]*attrDesc {
	m := make(map[string]*attrDesc)
	for _, attr := range attrs {
		m[attr.Name] = attr
	}
	return m
}
