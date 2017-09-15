// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package compiler generates sys descriptions of syscalls, types and resources
// from textual descriptions.
package compiler

import (
	"fmt"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
)

func (comp *compiler) check() {
	comp.checkNames()
	comp.checkFields()
	comp.checkTypes()
	// The subsequent, more complex, checks expect basic validity of the tree,
	// in particular corrent number of type arguments. If there were errors,
	// don't proceed to avoid out-of-bounds references to type arguments.
	if comp.errors != 0 {
		return
	}
	comp.checkUsed()
	comp.checkRecursion()
	comp.checkLenTargets()
	comp.checkConstructors()
	comp.checkVarlens()
}

func (comp *compiler) checkNames() {
	calls := make(map[string]*ast.Call)
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Resource, *ast.Struct:
			pos, typ, name := decl.Info()
			if reservedName[name] {
				comp.error(pos, "%v uses reserved name %v", typ, name)
				continue
			}
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
			if reservedName[name] {
				comp.error(n.Pos, "flags uses reserved name %v", name)
				continue
			}
			if prev := comp.intFlags[name]; prev != nil {
				comp.error(n.Pos, "flags %v redeclared, previously declared at %v",
					name, prev.Pos)
				continue
			}
			comp.intFlags[name] = n
		case *ast.StrFlags:
			n := decl.(*ast.StrFlags)
			name := n.Name.Name
			if reservedName[name] {
				comp.error(n.Pos, "string flags uses reserved name %v", name)
				continue
			}
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
			comp.checkType(n.Base, false, false, false, true)
		case *ast.Struct:
			for _, f := range n.Fields {
				comp.checkType(f.Type, false, false, !n.IsUnion, false)
			}
			comp.checkStruct(n)
		case *ast.Call:
			for _, a := range n.Args {
				comp.checkType(a.Type, true, false, false, false)
			}
			if n.Ret != nil {
				comp.checkType(n.Ret, true, true, false, false)
			}
		}
	}
}

func (comp *compiler) checkLenTargets() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			for _, arg := range n.Args {
				comp.checkLenType(arg.Type, arg.Name.Name, n.Args, nil, make(map[string]bool), true)
			}
		}
	}
}

func (comp *compiler) checkLenType(t *ast.Type, name string, fields []*ast.Field,
	parents []*ast.Struct, checked map[string]bool, isArg bool) {
	desc := comp.getTypeDesc(t)
	if desc == typeStruct {
		s := comp.structs[t.Ident]
		// Prune recursion, can happen even on correct tree via opt pointers.
		if checked[s.Name.Name] {
			return
		}
		checked[s.Name.Name] = true
		parents = append(parents, s)
		for _, fld := range s.Fields {
			comp.checkLenType(fld.Type, fld.Name.Name, s.Fields, parents, checked, false)
		}
		return
	}
	_, args, _ := comp.getArgsBase(t, "", prog.DirIn, isArg)
	for i, arg := range args {
		argDesc := desc.Args[i]
		if argDesc.Type == typeArgLenTarget {
			comp.checkLenTarget(t, name, arg.Ident, fields, parents)
		} else if argDesc.Type == typeArgType {
			comp.checkLenType(arg, name, fields, parents, checked, false)
		}
	}
}

func (comp *compiler) checkLenTarget(t *ast.Type, name, target string, fields []*ast.Field, parents []*ast.Struct) {
	if target == name {
		comp.error(t.Pos, "%v target %v refer to itself", t.Ident, target)
		return
	}
	if target == "parent" {
		if len(parents) == 0 {
			comp.error(t.Pos, "%v target %v does not exist", t.Ident, target)
		}
		return
	}
	for _, fld := range fields {
		if target != fld.Name.Name {
			continue
		}
		if fld.Type == t {
			comp.error(t.Pos, "%v target %v refer to itself", t.Ident, target)
		}
		return
	}
	for _, parent := range parents {
		if target == parent.Name.Name {
			return
		}
	}
	comp.error(t.Pos, "%v target %v does not exist", t.Ident, target)
}

func (comp *compiler) checkUsed() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			if n.NR == ^uint64(0) {
				break
			}
			for _, arg := range n.Args {
				comp.checkUsedType(arg.Type, true)
			}
			if n.Ret != nil {
				comp.checkUsedType(n.Ret, true)
			}
		}
	}
}

func (comp *compiler) checkUsedType(t *ast.Type, isArg bool) {
	if comp.used[t.Ident] {
		return
	}
	desc := comp.getTypeDesc(t)
	if desc == typeResource {
		r := comp.resources[t.Ident]
		for r != nil && !comp.used[r.Name.Name] {
			comp.used[r.Name.Name] = true
			r = comp.resources[r.Base.Ident]
		}
		return
	}
	if desc == typeStruct {
		comp.used[t.Ident] = true
		s := comp.structs[t.Ident]
		for _, fld := range s.Fields {
			comp.checkUsedType(fld.Type, false)
		}
		return
	}
	_, args, _ := comp.getArgsBase(t, "", prog.DirIn, isArg)
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.checkUsedType(arg, false)
		}
	}
}

type structDir struct {
	Struct string
	Dir    prog.Dir
}

func (comp *compiler) checkConstructors() {
	ctors := make(map[string]bool) // resources for which we have ctors
	checked := make(map[structDir]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			for _, arg := range n.Args {
				comp.checkTypeCtors(arg.Type, prog.DirIn, true, ctors, checked)
			}
			if n.Ret != nil {
				comp.checkTypeCtors(n.Ret, prog.DirOut, true, ctors, checked)
			}
		}
	}
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			name := n.Name.Name
			if !ctors[name] && comp.used[name] {
				comp.error(n.Pos, "resource %v can't be created"+
					" (never mentioned as a syscall return value or output argument/field)",
					name)
			}
		}
	}
}

func (comp *compiler) checkTypeCtors(t *ast.Type, dir prog.Dir, isArg bool,
	ctors map[string]bool, checked map[structDir]bool) {
	desc := comp.getTypeDesc(t)
	if desc == typeResource {
		// TODO(dvyukov): consider changing this to "dir == prog.DirOut".
		// We have few questionable cases where resources can be created
		// only by inout struct fields. These structs should be split
		// into two different structs: one is in and second is out.
		// But that will require attaching dir to individual fields.
		if dir != prog.DirIn {
			r := comp.resources[t.Ident]
			for r != nil && !ctors[r.Name.Name] {
				ctors[r.Name.Name] = true
				r = comp.resources[r.Base.Ident]
			}
		}
		return
	}
	if desc == typeStruct {
		s := comp.structs[t.Ident]
		name := s.Name.Name
		key := structDir{name, dir}
		if checked[key] {
			return
		}
		checked[key] = true
		for _, fld := range s.Fields {
			comp.checkTypeCtors(fld.Type, dir, false, ctors, checked)
		}
		return
	}
	if desc == typePtr {
		dir = genDir(t.Args[0])
	}
	_, args, _ := comp.getArgsBase(t, "", dir, isArg)
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.checkTypeCtors(arg, dir, false, ctors, checked)
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
			var path []pathElem
			comp.checkStructRecursion(checked, n, path)
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

func (comp *compiler) checkStructRecursion(checked map[string]bool, n *ast.Struct, path []pathElem) {
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
		comp.checkStructRecursion(checked, comp.structs[t.Ident], path)
		return
	}
	_, args, base := comp.getArgsBase(t, "", prog.DirIn, false)
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

func (comp *compiler) checkType(t *ast.Type, isArg, isRet, isStruct, isResourceBase bool) {
	if unexpected, _, ok := checkTypeKind(t, kindIdent); !ok {
		comp.error(t.Pos, "unexpected %v, expect type", unexpected)
		return
	}
	desc := comp.getTypeDesc(t)
	if desc == nil {
		comp.error(t.Pos, "unknown type %v", t.Ident)
		return
	}
	if t.HasColon {
		if !desc.AllowColon {
			comp.error(t.Pos2, "unexpected ':'")
			return
		}
		if !isStruct {
			comp.error(t.Pos2, "unexpected ':', only struct fields can be bitfields")
			return
		}
	}
	if isRet && (!desc.CanBeArg || desc.CantBeRet) {
		comp.error(t.Pos, "%v can't be syscall return", t.Ident)
		return
	}
	if isArg && !desc.CanBeArg {
		comp.error(t.Pos, "%v can't be syscall argument", t.Ident)
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
			comp.checkType(arg, false, isRet, false, false)
		} else {
			comp.checkTypeArg(t, arg, desc.Args[i])
		}
	}
	if err0 != comp.errors {
		return
	}
	if desc.Check != nil {
		_, args, base := comp.getArgsBase(t, "", prog.DirIn, isArg)
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

func (comp *compiler) checkVarlens() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			comp.checkVarlen(n)
		}
	}
}

func (comp *compiler) isVarlen(t *ast.Type) bool {
	desc, args, base := comp.getArgsBase(t, "", prog.DirIn, false)
	return desc.Varlen != nil && desc.Varlen(comp, t, args, base)
}

func (comp *compiler) checkVarlen(n *ast.Struct) {
	// Non-varlen unions can't have varlen fields.
	// Non-packed structs can't have varlen fields in the middle.
	if n.IsUnion {
		if varlen := comp.parseUnionAttrs(n); varlen {
			return
		}
	} else {
		if packed, _ := comp.parseStructAttrs(n); packed {
			return
		}
	}
	for i, f := range n.Fields {
		if !n.IsUnion && i == len(n.Fields)-1 {
			break
		}
		if comp.isVarlen(f.Type) {
			if n.IsUnion {
				comp.error(f.Pos, "variable size field %v in non-varlen union %v",
					f.Name.Name, n.Name.Name)
			} else {
				comp.error(f.Pos, "variable size field %v in the middle of non-packed struct %v",
					f.Name.Name, n.Name.Name)
			}
		}
	}
}
