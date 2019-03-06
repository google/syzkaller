// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package compiler generates sys descriptions of syscalls, types and resources
// from textual descriptions.
package compiler

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func (comp *compiler) typecheck() {
	comp.checkDirectives()
	comp.checkNames()
	comp.checkFields()
	comp.checkTypedefs()
	comp.checkTypes()
}

func (comp *compiler) check() {
	comp.checkTypeValues()
	comp.checkAttributeValues()
	comp.checkUnused()
	comp.checkRecursion()
	comp.checkLenTargets()
	comp.checkConstructors()
	comp.checkVarlens()
	comp.checkDupConsts()
}

func (comp *compiler) checkDirectives() {
	includes := make(map[string]bool)
	incdirs := make(map[string]bool)
	defines := make(map[string]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Include:
			name := n.File.Value
			path := n.Pos.File + "/" + name
			if includes[path] {
				comp.error(n.Pos, "duplicate include %q", name)
			}
			includes[path] = true
		case *ast.Incdir:
			name := n.Dir.Value
			path := n.Pos.File + "/" + name
			if incdirs[path] {
				comp.error(n.Pos, "duplicate incdir %q", name)
			}
			incdirs[path] = true
		case *ast.Define:
			name := n.Name.Name
			path := n.Pos.File + "/" + name
			if defines[path] {
				comp.error(n.Pos, "duplicate define %v", name)
			}
			defines[path] = true
		}
	}
}

func (comp *compiler) checkNames() {
	calls := make(map[string]*ast.Call)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource, *ast.Struct, *ast.TypeDef:
			pos, typ, name := decl.Info()
			if reservedName[name] {
				comp.error(pos, "%v uses reserved name %v", typ, name)
				continue
			}
			if builtinTypes[name] != nil || builtinTypedefs[name] != nil {
				comp.error(pos, "%v name %v conflicts with builtin type", typ, name)
				continue
			}
			if prev := comp.resources[name]; prev != nil {
				comp.error(pos, "type %v redeclared, previously declared as resource at %v",
					name, prev.Pos)
				continue
			}
			if prev := comp.typedefs[name]; prev != nil {
				comp.error(pos, "type %v redeclared, previously declared as type alias at %v",
					name, prev.Pos)
				continue
			}
			if prev := comp.structs[name]; prev != nil {
				_, typ, _ := prev.Info()
				comp.error(pos, "type %v redeclared, previously declared as %v at %v",
					name, typ, prev.Pos)
				continue
			}
			switch n := decl.(type) {
			case *ast.Resource:
				comp.resources[name] = n
			case *ast.TypeDef:
				comp.typedefs[name] = n
			case *ast.Struct:
				comp.structs[name] = n
			}
		case *ast.IntFlags:
			name := n.Name.Name
			if name == "_" {
				continue
			}
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
			name := n.Name.Name
			if reservedName[name] {
				comp.error(n.Pos, "string flags uses reserved name %v", name)
				continue
			}
			if builtinStrFlags[name] != nil {
				comp.error(n.Pos, "string flags %v conflicts with builtin flags", name)
				continue
			}
			if prev := comp.strFlags[name]; prev != nil {
				comp.error(n.Pos, "string flags %v redeclared, previously declared at %v",
					name, prev.Pos)
				continue
			}
			comp.strFlags[name] = n
		case *ast.Call:
			name := n.Name.Name
			if prev := calls[name]; prev != nil {
				comp.error(n.Pos, "syscall %v redeclared, previously declared at %v",
					name, prev.Pos)
			}
			calls[name] = n
		}
	}
}

func (comp *compiler) checkFields() {
	const maxArgs = 9 // executor does not support more
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			_, typ, name := n.Info()
			comp.checkStructFields(n, typ, name)
		case *ast.TypeDef:
			if n.Struct != nil {
				_, typ, _ := n.Struct.Info()
				comp.checkStructFields(n.Struct, "template "+typ, n.Name.Name)
			}
		case *ast.Call:
			name := n.Name.Name
			comp.checkFieldGroup(n.Args, "argument", "syscall "+name)
			if len(n.Args) > maxArgs {
				comp.error(n.Pos, "syscall %v has %v arguments, allowed maximum is %v",
					name, len(n.Args), maxArgs)
			}
		}
	}
}

func (comp *compiler) checkStructFields(n *ast.Struct, typ, name string) {
	comp.checkFieldGroup(n.Fields, "field", typ+" "+name)
	if len(n.Fields) < 1 {
		comp.error(n.Pos, "%v %v has no fields, need at least 1 field", typ, name)
	}
}

func (comp *compiler) checkFieldGroup(fields []*ast.Field, what, ctx string) {
	existing := make(map[string]bool)
	for _, f := range fields {
		fn := f.Name.Name
		if fn == "parent" {
			comp.error(f.Pos, "reserved %v name %v in %v", what, fn, ctx)
		}
		if existing[fn] {
			comp.error(f.Pos, "duplicate %v %v in %v", what, fn, ctx)
		}
		existing[fn] = true
	}
}

func (comp *compiler) checkTypedefs() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.TypeDef:
			if len(n.Args) == 0 {
				// Non-template types are fully typed, so we check them ahead of time.
				err0 := comp.errors
				comp.checkType(checkCtx{}, n.Type, checkIsTypedef)
				if err0 != comp.errors {
					// To not produce confusing errors on broken type usage.
					delete(comp.typedefs, n.Name.Name)
				}
			} else {
				// For templates we only do basic checks of arguments.
				names := make(map[string]bool)
				for _, arg := range n.Args {
					if names[arg.Name] {
						comp.error(arg.Pos, "duplicate type argument %v", arg.Name)
					}
					names[arg.Name] = true
					for _, c := range arg.Name {
						if c >= 'A' && c <= 'Z' ||
							c >= '0' && c <= '9' ||
							c == '_' {
							continue
						}
						comp.error(arg.Pos, "type argument %v must be ALL_CAPS",
							arg.Name)
						break
					}
				}
			}
		}
	}
}

func (comp *compiler) checkTypes() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			comp.checkType(checkCtx{}, n.Base, checkIsResourceBase)
		case *ast.Struct:
			comp.checkStruct(checkCtx{}, n)
		case *ast.Call:
			for _, a := range n.Args {
				comp.checkType(checkCtx{}, a.Type, checkIsArg)
			}
			if n.Ret != nil {
				comp.checkType(checkCtx{}, n.Ret, checkIsArg|checkIsRet)
			}
		}
	}
}

func (comp *compiler) checkTypeValues() {
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Call, *ast.Struct, *ast.Resource, *ast.TypeDef:
			comp.foreachType(decl, func(t *ast.Type, desc *typeDesc,
				args []*ast.Type, base prog.IntTypeCommon) {
				if desc.CheckConsts != nil {
					desc.CheckConsts(comp, t, args, base)
				}
				for i, arg := range args {
					if check := desc.Args[i].Type.CheckConsts; check != nil {
						check(comp, arg)
					}
				}
			})
		}
	}
}

func (comp *compiler) checkAttributeValues() {
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			for _, attr := range n.Attrs {
				if attr.Ident == "size" {
					_, typ, name := n.Info()
					if comp.structIsVarlen(n.Name.Name) {
						comp.error(attr.Pos, "varlen %v %v has size attribute",
							typ, name)
					}
					sz := attr.Args[0].Value
					if sz == 0 || sz > 1<<20 {
						comp.error(attr.Args[0].Pos, "size attribute has bad value %v"+
							", expect [1, 1<<20]", sz)
					}
				}
			}
		}
	}
}

func (comp *compiler) checkLenTargets() {
	warned := make(map[string]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			for _, arg := range n.Args {
				checked := make(map[string]bool)
				comp.checkLenType(arg.Type, arg.Name.Name, n.Args, nil, checked, warned, true)
			}
		}
	}
}

func (comp *compiler) checkLenType(t *ast.Type, name string, fields []*ast.Field,
	parents []string, checked, warned map[string]bool, isArg bool) {
	desc := comp.getTypeDesc(t)
	if desc == typeStruct {
		s := comp.structs[t.Ident]
		// Prune recursion, can happen even on correct tree via opt pointers.
		if checked[s.Name.Name] {
			return
		}
		checked[s.Name.Name] = true
		parentName := s.Name.Name
		if pos := strings.IndexByte(parentName, '['); pos != -1 {
			// For template parents name is "struct_name[ARG1, ARG2]", strip the part after '['.
			parentName = parentName[:pos]
		}
		parents = append(parents, parentName)
		if !s.IsUnion {
			fields = s.Fields
		}
		for _, fld := range s.Fields {
			comp.checkLenType(fld.Type, fld.Name.Name, fields, parents, checked, warned, false)
		}
		warned[parentName] = true
		return
	}
	_, args, _ := comp.getArgsBase(t, "", prog.DirIn, isArg)
	for i, arg := range args {
		argDesc := desc.Args[i]
		if argDesc.Type == typeArgLenTarget {
			comp.checkLenTarget(t, name, arg.Ident, fields, parents, warned)
		} else if argDesc.Type == typeArgType {
			comp.checkLenType(arg, name, fields, parents, checked, warned, argDesc.IsArg)
		}
	}
}

func (comp *compiler) checkLenTarget(t *ast.Type, name, target string, fields []*ast.Field,
	parents []string, warned map[string]bool) {
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
		if t.Ident == "len" {
			inner := fld.Type
			desc, args, _ := comp.getArgsBase(inner, "", prog.DirIn, false)
			for desc == typePtr {
				if desc != typePtr {
					break
				}
				inner = args[1]
				desc, args, _ = comp.getArgsBase(inner, "", prog.DirIn, false)
			}
			if desc == typeArray && comp.isVarlen(args[0]) {
				// We can reach the same struct multiple times starting from different
				// syscall arguments. Warn only once.
				if len(parents) == 0 || !warned[parents[len(parents)-1]] {
					comp.warning(t.Pos, "len target %v refer to an array with"+
						" variable-size elements (do you mean bytesize?)", target)
				}
			}
		}
		return
	}
	for _, parent := range parents {
		if target == parent {
			return
		}
	}
	comp.error(t.Pos, "%v target %v does not exist", t.Ident, target)
}

func CollectUnused(desc *ast.Description, target *targets.Target, eh ast.ErrorHandler) ([]ast.Node, error) {
	comp := createCompiler(desc, target, eh)
	comp.typecheck()
	if comp.errors > 0 {
		return nil, errors.New("typecheck failed")
	}

	nodes := comp.collectUnused()
	if comp.errors > 0 {
		return nil, errors.New("collectUnused failed")
	}
	return nodes, nil
}

func (comp *compiler) collectUnused() []ast.Node {
	var unused []ast.Node

	comp.used, _, _ = comp.collectUsed(false)
	structs, flags, strflags := comp.collectUsed(true)
	_, _, _ = structs, flags, strflags

	for name, n := range comp.intFlags {
		if !flags[name] {
			unused = append(unused, n)
		}
	}
	for name, n := range comp.strFlags {
		if !strflags[name] && builtinStrFlags[name] == nil {
			unused = append(unused, n)
		}
	}
	for name, n := range comp.resources {
		if !structs[name] {
			unused = append(unused, n)
		}
	}
	for name, n := range comp.structs {
		if !structs[name] {
			unused = append(unused, n)
		}
	}
	for name, n := range comp.typedefs {
		if !comp.usedTypedefs[name] {
			unused = append(unused, n)
		}
	}

	return unused
}

func (comp *compiler) collectUsed(all bool) (structs, flags, strflags map[string]bool) {
	structs = make(map[string]bool)
	flags = make(map[string]bool)
	strflags = make(map[string]bool)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			if !all && n.NR == ^uint64(0) {
				break
			}
			for _, arg := range n.Args {
				comp.collectUsedType(structs, flags, strflags, arg.Type, true)
			}
			if n.Ret != nil {
				comp.collectUsedType(structs, flags, strflags, n.Ret, true)
			}
		}
	}
	return
}

func (comp *compiler) collectUsedType(structs, flags, strflags map[string]bool, t *ast.Type, isArg bool) {
	desc := comp.getTypeDesc(t)
	if desc == typeResource {
		r := comp.resources[t.Ident]
		for r != nil && !structs[r.Name.Name] {
			structs[r.Name.Name] = true
			r = comp.resources[r.Base.Ident]
		}
		return
	}
	if desc == typeStruct {
		if structs[t.Ident] {
			return
		}
		structs[t.Ident] = true
		s := comp.structs[t.Ident]
		for _, fld := range s.Fields {
			comp.collectUsedType(structs, flags, strflags, fld.Type, false)
		}
		return
	}
	if desc == typeFlags {
		flags[t.Args[0].Ident] = true
		return
	}
	if desc == typeString {
		if len(t.Args) != 0 && t.Args[0].Ident != "" {
			strflags[t.Args[0].Ident] = true
		}
		return
	}
	_, args, _ := comp.getArgsBase(t, "", prog.DirIn, isArg)
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.collectUsedType(structs, flags, strflags, arg, desc.Args[i].IsArg)
		}
	}
}

func (comp *compiler) checkUnused() {
	for _, n := range comp.collectUnused() {
		pos, typ, name := n.Info()
		comp.error(pos, fmt.Sprintf("unused %v %v", typ, name))
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
			comp.checkTypeCtors(arg, dir, desc.Args[i].IsArg, ctors, checked)
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

func (comp *compiler) checkStruct(ctx checkCtx, n *ast.Struct) {
	var flags checkFlags
	if !n.IsUnion {
		flags |= checkIsStruct
	}
	for _, f := range n.Fields {
		comp.checkType(ctx, f.Type, flags)
	}
	for _, attr := range n.Attrs {
		if unexpected, _, ok := checkTypeKind(attr, kindIdent); !ok {
			comp.error(attr.Pos, "unexpected %v, expect attribute", unexpected)
			return
		}
		if attr.HasColon {
			comp.error(attr.Pos2, "unexpected ':'")
			return
		}
	}
	if n.IsUnion {
		comp.parseUnionAttrs(n)
	} else {
		comp.parseStructAttrs(n)
	}
}

type checkFlags int

const (
	checkIsArg          checkFlags = 1 << iota // immediate syscall arg type
	checkIsRet                                 // immediate syscall ret type
	checkIsStruct                              // immediate struct field type
	checkIsResourceBase                        // immediate resource base type
	checkIsTypedef                             // immediate type alias/template type
)

type checkCtx struct {
	instantiationStack []string
}

func (comp *compiler) checkType(ctx checkCtx, t *ast.Type, flags checkFlags) {
	if unexpected, _, ok := checkTypeKind(t, kindIdent); !ok {
		comp.error(t.Pos, "unexpected %v, expect type", unexpected)
		return
	}
	desc := comp.getTypeDesc(t)
	if desc == nil {
		comp.error(t.Pos, "unknown type %v", t.Ident)
		return
	}
	if desc == typeTypedef {
		err0 := comp.errors
		// Replace t with type alias/template target type inplace,
		// and check the replaced type recursively.
		comp.replaceTypedef(&ctx, t, flags)
		if err0 == comp.errors {
			comp.checkType(ctx, t, flags)
		}
		return
	}
	err0 := comp.errors
	comp.checkTypeBasic(t, desc, flags)
	if err0 != comp.errors {
		return
	}
	args := comp.checkTypeArgs(t, desc, flags)
	if err0 != comp.errors {
		return
	}
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			var innerFlags checkFlags
			if desc.Args[i].IsArg {
				innerFlags |= checkIsArg
			}
			comp.checkType(ctx, arg, innerFlags)
		} else {
			comp.checkTypeArg(t, arg, desc.Args[i])
		}
	}
	if err0 != comp.errors {
		return
	}
	if desc.Check != nil {
		_, args, base := comp.getArgsBase(t, "", prog.DirIn, flags&checkIsArg != 0)
		desc.Check(comp, t, args, base)
	}
}

func (comp *compiler) checkTypeBasic(t *ast.Type, desc *typeDesc, flags checkFlags) {
	if t.HasColon {
		if !desc.AllowColon {
			comp.error(t.Pos2, "unexpected ':'")
			return
		}
		if flags&checkIsStruct == 0 {
			comp.error(t.Pos2, "unexpected ':', only struct fields can be bitfields")
			return
		}
	}
	if flags&checkIsTypedef != 0 && !desc.CanBeTypedef {
		comp.error(t.Pos, "%v can't be type alias target", t.Ident)
		return
	}
	if flags&checkIsResourceBase != 0 &&
		(desc.CanBeResourceBase == nil || !desc.CanBeResourceBase(comp, t)) {
		comp.error(t.Pos, "%v can't be resource base (int types can)", t.Ident)
		return
	}
	canBeArg, canBeRet := false, false
	if desc.CanBeArgRet != nil {
		canBeArg, canBeRet = desc.CanBeArgRet(comp, t)
	}
	if flags&checkIsRet != 0 && !canBeRet {
		comp.error(t.Pos, "%v can't be syscall return", t.Ident)
		return
	}
	if flags&checkIsArg != 0 && !canBeArg {
		comp.error(t.Pos, "%v can't be syscall argument", t.Ident)
		return
	}
}

func (comp *compiler) checkTypeArgs(t *ast.Type, desc *typeDesc, flags checkFlags) []*ast.Type {
	args, opt := removeOpt(t)
	if opt != nil {
		if len(opt.Args) != 0 {
			comp.error(opt.Pos, "opt can't have arguments")
		}
		if flags&checkIsResourceBase != 0 || desc.CantBeOpt {
			what := "resource base"
			if desc.CantBeOpt {
				what = t.Ident
			}
			comp.error(opt.Pos, "%v can't be marked as opt", what)
			return nil
		}
	}
	addArgs := 0
	needBase := flags&checkIsArg == 0 && desc.NeedBase
	if needBase {
		addArgs++ // last arg must be base type, e.g. const[0, int32]
	}
	if len(args) > len(desc.Args)+addArgs || len(args) < len(desc.Args)-desc.OptArgs+addArgs {
		comp.error(t.Pos, "wrong number of arguments for type %v, expect %v",
			t.Ident, expectedTypeArgs(desc, needBase))
		return nil
	}
	if needBase {
		base := args[len(args)-1]
		args = args[:len(args)-1]
		comp.checkTypeArg(t, base, typeArgBase)
	}
	return args
}

func (comp *compiler) replaceTypedef(ctx *checkCtx, t *ast.Type, flags checkFlags) {
	typedefName := t.Ident
	comp.usedTypedefs[typedefName] = true
	if t.HasColon {
		comp.error(t.Pos, "type alias %v with ':'", t.Ident)
		return
	}
	typedef := comp.typedefs[typedefName]
	fullTypeName := ast.SerializeNode(t)
	for i, prev := range ctx.instantiationStack {
		if prev == fullTypeName {
			ctx.instantiationStack = append(ctx.instantiationStack, fullTypeName)
			path := ""
			for j := i; j < len(ctx.instantiationStack); j++ {
				if j != i {
					path += " -> "
				}
				path += ctx.instantiationStack[j]
			}
			comp.error(t.Pos, "type instantiation loop: %v", path)
			return
		}
	}
	ctx.instantiationStack = append(ctx.instantiationStack, fullTypeName)
	nargs := len(typedef.Args)
	args := t.Args
	if nargs != len(t.Args) {
		if nargs == 0 {
			comp.error(t.Pos, "type %v is not a template", typedefName)
		} else {
			comp.error(t.Pos, "template %v needs %v arguments instead of %v",
				typedefName, nargs, len(t.Args))
		}
		return
	}
	pos0 := t.Pos
	if typedef.Type != nil {
		*t = *typedef.Type.Clone().(*ast.Type)
		if !comp.instantiate(t, typedef.Args, args) {
			return
		}
	} else {
		if comp.structs[fullTypeName] == nil {
			inst := typedef.Struct.Clone().(*ast.Struct)
			inst.Name.Name = fullTypeName
			if !comp.instantiate(inst, typedef.Args, args) {
				return
			}
			comp.checkStruct(*ctx, inst)
			comp.desc.Nodes = append(comp.desc.Nodes, inst)
			comp.structs[fullTypeName] = inst
		}
		*t = ast.Type{
			Ident: fullTypeName,
		}
	}
	t.Pos = pos0

	// Remove base type if it's not needed in this context.
	// If desc is nil, will return an error later when we typecheck the result.
	desc := comp.getTypeDesc(t)
	if desc != nil && flags&checkIsArg != 0 && desc.NeedBase {
		baseTypePos := len(t.Args) - 1
		if t.Args[baseTypePos].Ident == "opt" {
			baseTypePos--
		}
		copy(t.Args[baseTypePos:], t.Args[baseTypePos+1:])
		t.Args = t.Args[:len(t.Args)-1]
	}
}

func (comp *compiler) instantiate(templ ast.Node, params []*ast.Ident, args []*ast.Type) bool {
	if len(params) == 0 {
		return true
	}
	argMap := make(map[string]*ast.Type)
	for i, param := range params {
		argMap[param.Name] = args[i]
	}
	err0 := comp.errors
	templ.Walk(ast.Recursive(func(n ast.Node) {
		templArg, ok := n.(*ast.Type)
		if !ok {
			return
		}
		if concreteArg := argMap[templArg.Ident]; concreteArg != nil {
			origArgs := templArg.Args
			if len(origArgs) != 0 && len(concreteArg.Args) != 0 {
				comp.error(templArg.Pos, "both template parameter %v and its usage"+
					" have sub-arguments", templArg.Ident)
				return
			}
			*templArg = *concreteArg.Clone().(*ast.Type)
			if len(origArgs) != 0 {
				templArg.Args = origArgs
			}
		}
		// TODO(dvyukov): somewhat hacky, but required for int8[0:CONST_ARG]
		// Need more checks here. E.g. that CONST_ARG does not have subargs.
		// And if CONST_ARG is a value, then use concreteArg.Value.
		// Also need to error if CONST_ARG is a string.
		if concreteArg := argMap[templArg.Ident2]; concreteArg != nil {
			templArg.Ident2 = concreteArg.Ident
			templArg.Pos2 = concreteArg.Pos
		}
	}))
	return err0 == comp.errors
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
	if len(arg.Args) > desc.MaxArgs {
		comp.error(arg.Pos, "%v argument has subargs", argDesc.Name)
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
	case t.HasString:
		ok = kind == kindString
		if !ok {
			unexpected = fmt.Sprintf("string %q", t.String)
		}
	case t.Ident != "":
		ok = kind == kindIdent || kind == kindInt
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
	desc, args, _ := comp.getArgsBase(t, "", prog.DirIn, false)
	return desc.Varlen != nil && desc.Varlen(comp, t, args)
}

func (comp *compiler) isZeroSize(t *ast.Type) bool {
	desc, args, _ := comp.getArgsBase(t, "", prog.DirIn, false)
	return desc.ZeroSize != nil && desc.ZeroSize(comp, t, args)
}

func (comp *compiler) checkVarlen(n *ast.Struct) {
	// Non-varlen unions can't have varlen fields.
	// Non-packed structs can't have varlen fields in the middle.
	if n.IsUnion {
		if varlen, _ := comp.parseUnionAttrs(n); varlen {
			return
		}
	} else {
		if packed, _, _ := comp.parseStructAttrs(n); packed {
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

func (comp *compiler) checkDupConsts() {
	// The idea is to detect copy-paste errors in const arguments, e.g.:
	//   call$FOO(fd fd, arg const[FOO])
	//   call$BAR(fd fd, arg const[FOO])
	// The second one is meant to be const[BAR],
	// Unfortunately, this does not fully work as it detects lots of false positives.
	// But was useful to find real bugs as well. So for now it's disabled, but can be run manually.
	if true {
		return
	}
	dups := make(map[string]map[string]dupConstArg)
	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Call:
			comp.checkDupConstsCall(n, dups)
		}
	}
}

type dupConstArg struct {
	pos  ast.Pos
	name string
}

func (comp *compiler) checkDupConstsCall(n *ast.Call, dups map[string]map[string]dupConstArg) {
	if n.NR == ^uint64(0) {
		return
	}
	for dups[n.CallName] == nil {
		dups[n.CallName] = make(map[string]dupConstArg)
	}
	hasConsts := false
	constArgID := ""
	for i, arg := range n.Args {
		desc := comp.getTypeDesc(arg.Type)
		if desc == typeConst {
			v := arg.Type.Args[0].Value
			if v != 0 && v != 18446744073709551516 { // AT_FDCWD
				constArgID += fmt.Sprintf("(%v-%v)", i, fmt.Sprintf("%v", v))
				hasConsts = true
			}
		} else if desc == typeResource {
			constArgID += fmt.Sprintf("(%v-%v)", i, arg.Type.Ident)
		}
	}
	if !hasConsts {
		return
	}
	dup, ok := dups[n.CallName][constArgID]
	if !ok {
		dups[n.CallName][constArgID] = dupConstArg{
			pos:  n.Pos,
			name: n.Name.Name,
		}
		return
	}
	comp.error(n.Pos, "call %v: duplicate const %v, previously used in call %v at %v",
		n.Name.Name, constArgID, dup.name, dup.pos)
}
