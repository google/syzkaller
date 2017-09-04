// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package compiler generates sys descriptions of syscalls, types and resources
// from textual descriptions.
package compiler

import (
	"fmt"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

func (comp *compiler) check() {
	// TODO: check len in syscall arguments referring to parent.
	// TODO: incorrect name is referenced in len type
	// TODO: no constructor for a resource

	comp.checkNames()
	comp.checkFields()
	comp.checkTypes()
	comp.checkRecursion()
}

func (comp *compiler) checkNames() {
	calls := make(map[string]*ast.Call)
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Resource, *ast.Struct:
			pos, typ, name := decl.Info()
			if builtinTypes[name] != nil {
				comp.error(pos, "%v name %v conflicts with builtin type", typ, name)
				continue
			}
			if prev := comp.resources[name]; prev != nil {
				comp.error(pos, "type %v redeclared, previously declared as resource at %v",
					name, prev.Pos)
				continue
			}
			if prev := comp.structs[name]; prev != nil {
				_, typ, _ := prev.Info()
				comp.error(pos, "type %v redeclared, previously declared as %v at %v",
					name, typ, prev.Pos)
				continue
			}
			if res, ok := decl.(*ast.Resource); ok {
				comp.resources[name] = res
			} else if str, ok := decl.(*ast.Struct); ok {
				comp.structs[name] = str
			}
		case *ast.IntFlags:
			n := decl.(*ast.IntFlags)
			name := n.Name.Name
			if prev := comp.intFlags[name]; prev != nil {
				comp.error(n.Pos, "flags %v redeclared, previously declared at %v",
					name, prev.Pos)
				continue
			}
			comp.intFlags[name] = n
		case *ast.StrFlags:
			n := decl.(*ast.StrFlags)
			name := n.Name.Name
			if prev := comp.strFlags[name]; prev != nil {
				comp.error(n.Pos, "string flags %v redeclared, previously declared at %v",
					name, prev.Pos)
				continue
			}
			comp.strFlags[name] = n
		case *ast.Call:
			c := decl.(*ast.Call)
			name := c.Name.Name
			if prev := calls[name]; prev != nil {
				comp.error(c.Pos, "syscall %v redeclared, previously declared at %v",
					name, prev.Pos)
			}
			calls[name] = c
		}
	}
}

func (comp *compiler) checkFields() {
	const maxArgs = 9 // executor does not support more
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			_, typ, name := n.Info()
			fields := make(map[string]bool)
			for _, f := range n.Fields {
				fn := f.Name.Name
				if fn == "parent" {
					comp.error(f.Pos, "reserved field name %v in %v %v", fn, typ, name)
				}
				if fields[fn] {
					comp.error(f.Pos, "duplicate field %v in %v %v", fn, typ, name)
				}
				fields[fn] = true
			}
			if !n.IsUnion && len(n.Fields) < 1 {
				comp.error(n.Pos, "struct %v has no fields, need at least 1 field", name)
			}
			if n.IsUnion && len(n.Fields) < 2 {
				comp.error(n.Pos, "union %v has only %v field, need at least 2 fields",
					name, len(n.Fields))
			}
		case *ast.Call:
			name := n.Name.Name
			args := make(map[string]bool)
			for _, a := range n.Args {
				an := a.Name.Name
				if an == "parent" {
					comp.error(a.Pos, "reserved argument name %v in syscall %v",
						an, name)
				}
				if args[an] {
					comp.error(a.Pos, "duplicate argument %v in syscall %v",
						an, name)
				}
				args[an] = true
			}
			if len(n.Args) > maxArgs {
				comp.error(n.Pos, "syscall %v has %v arguments, allowed maximum is %v",
					name, len(n.Args), maxArgs)
			}
		}
	}
}

func (comp *compiler) checkTypes() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			comp.checkType(n.Base, false, true)
		case *ast.Struct:
			for _, f := range n.Fields {
				comp.checkType(f.Type, false, false)
			}
			comp.checkStruct(n)
		case *ast.Call:
			for _, a := range n.Args {
				comp.checkType(a.Type, true, false)
			}
			if n.Ret != nil {
				comp.checkType(n.Ret, true, false)
			}
		}
	}
}

func (comp *compiler) checkRecursion() {
	checked := make(map[string]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			comp.checkResourceRecursion(n)
		case *ast.Struct:
			comp.checkStructRecursion(checked, n)
		}
	}
}

func (comp *compiler) checkResourceRecursion(n *ast.Resource) {
	var seen []string
	for n != nil {
		if arrayContains(seen, n.Name.Name) {
			chain := ""
			for _, r := range seen {
				chain += r + "->"
			}
			chain += n.Name.Name
			comp.error(n.Pos, "recursive resource %v", chain)
			return
		}
		seen = append(seen, n.Name.Name)
		n = comp.resources[n.Base.Ident]
	}
}

type pathElem struct {
	Pos    ast.Pos
	Struct string
	Field  string
}

func (comp *compiler) checkStructRecursion(checked map[string]bool, n *ast.Struct) {
	var path []pathElem
	comp.checkStructRecursion1(checked, n, path)
}

func (comp *compiler) checkStructRecursion1(checked map[string]bool, n *ast.Struct, path []pathElem) {
	name := n.Name.Name
	if checked[name] {
		return
	}
	for i, elem := range path {
		if elem.Struct != name {
			continue
		}
		path = path[i:]
		str := ""
		for _, elem := range path {
			str += fmt.Sprintf("%v.%v -> ", elem.Struct, elem.Field)
		}
		str += name
		comp.error(path[0].Pos, "recursive declaration: %v (mark some pointers as opt)", str)
		checked[name] = true
		return
	}
	for _, f := range n.Fields {
		path = append(path, pathElem{
			Pos:    f.Pos,
			Struct: name,
			Field:  f.Name.Name,
		})
		comp.recurseField(checked, f.Type, path)
		path = path[:len(path)-1]
	}
	checked[name] = true
}

func (comp *compiler) recurseField(checked map[string]bool, t *ast.Type, path []pathElem) {
	desc := comp.getTypeDesc(t)
	if desc == typeStruct {
		comp.checkStructRecursion1(checked, comp.structs[t.Ident], path)
		return
	}
	_, args, base := comp.getArgsBase(t, "", sys.DirIn, false)
	if desc == typePtr && base.IsOptional {
		return // optional pointers prune recursion
	}
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.recurseField(checked, arg, path)
		}
	}
}

func (comp *compiler) checkStruct(n *ast.Struct) {
	if n.IsUnion {
		comp.parseUnionAttrs(n)
	} else {
		comp.parseStructAttrs(n)
	}
}

func (comp *compiler) checkType(t *ast.Type, isArg, isResourceBase bool) {
	if unexpected, _, ok := checkTypeKind(t, kindIdent); !ok {
		comp.error(t.Pos, "unexpected %v, expect type", unexpected)
		return
	}
	desc := comp.getTypeDesc(t)
	if desc == nil {
		comp.error(t.Pos, "unknown type %v", t.Ident)
		return
	}
	if !desc.AllowColon && t.HasColon {
		comp.error(t.Pos2, "unexpected ':'")
		return
	}
	if isArg && !desc.CanBeArg {
		comp.error(t.Pos, "%v can't be syscall argument/return", t.Ident)
		return
	}
	if isResourceBase && !desc.ResourceBase {
		comp.error(t.Pos, "%v can't be resource base (int types can)", t.Ident)
		return
	}
	args, opt := removeOpt(t)
	if opt && (desc.CantBeOpt || isResourceBase) {
		what := "resource base"
		if desc.CantBeOpt {
			what = t.Ident
		}
		pos := t.Args[len(t.Args)-1].Pos
		comp.error(pos, "%v can't be marked as opt", what)
		return
	}
	addArgs := 0
	needBase := !isArg && desc.NeedBase
	if needBase {
		addArgs++ // last arg must be base type, e.g. const[0, int32]
	}
	if len(args) > len(desc.Args)+addArgs || len(args) < len(desc.Args)-desc.OptArgs+addArgs {
		comp.error(t.Pos, "wrong number of arguments for type %v, expect %v",
			t.Ident, expectedTypeArgs(desc, needBase))
		return
	}
	if needBase {
		base := args[len(args)-1]
		args = args[:len(args)-1]
		comp.checkTypeArg(t, base, typeArgBase)
	}
	err0 := comp.errors
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.checkType(arg, false, false)
		} else {
			comp.checkTypeArg(t, arg, desc.Args[i])
		}
	}
	if err0 != comp.errors {
		return
	}
	if desc.Check != nil {
		_, args, base := comp.getArgsBase(t, "", sys.DirIn, isArg)
		desc.Check(comp, t, args, base)
	}
}

func (comp *compiler) checkTypeArg(t, arg *ast.Type, argDesc namedArg) {
	desc := argDesc.Type
	if len(desc.Names) != 0 {
		if unexpected, _, ok := checkTypeKind(arg, kindIdent); !ok {
			comp.error(arg.Pos, "unexpected %v for %v argument of %v type, expect %+v",
				unexpected, argDesc.Name, t.Ident, desc.Names)
			return
		}
		if !arrayContains(desc.Names, arg.Ident) {
			comp.error(arg.Pos, "unexpected value %v for %v argument of %v type, expect %+v",
				arg.Ident, argDesc.Name, t.Ident, desc.Names)
			return
		}
	} else {
		if unexpected, expect, ok := checkTypeKind(arg, desc.Kind); !ok {
			comp.error(arg.Pos, "unexpected %v for %v argument of %v type, expect %v",
				unexpected, argDesc.Name, t.Ident, expect)
			return
		}
	}
	if !desc.AllowColon && arg.HasColon {
		comp.error(arg.Pos2, "unexpected ':'")
		return
	}
	if desc.Check != nil {
		desc.Check(comp, arg)
	}
}

func expectedTypeArgs(desc *typeDesc, needBase bool) string {
	expect := ""
	for i, arg := range desc.Args {
		if expect != "" {
			expect += ", "
		}
		opt := i >= len(desc.Args)-desc.OptArgs
		if opt {
			expect += "["
		}
		expect += arg.Name
		if opt {
			expect += "]"
		}
	}
	if needBase {
		if expect != "" {
			expect += ", "
		}
		expect += typeArgBase.Name
	}
	if !desc.CantBeOpt {
		if expect != "" {
			expect += ", "
		}
		expect += "[opt]"
	}
	if expect == "" {
		expect = "no arguments"
	}
	return expect
}

func checkTypeKind(t *ast.Type, kind int) (unexpected string, expect string, ok bool) {
	switch {
	case kind == kindAny:
		ok = true
	case t.String != "":
		ok = kind == kindString
		if !ok {
			unexpected = fmt.Sprintf("string %q", t.String)
		}
	case t.Ident != "":
		ok = kind == kindIdent
		if !ok {
			unexpected = fmt.Sprintf("identifier %v", t.Ident)
		}
	default:
		ok = kind == kindInt
		if !ok {
			unexpected = fmt.Sprintf("int %v", t.Value)
		}
	}
	if !ok {
		switch kind {
		case kindString:
			expect = "string"
		case kindIdent:
			expect = "identifier"
		case kindInt:
			expect = "int"
		}
	}
	return
}
