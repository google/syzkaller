// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package compiler generates sys descriptions of syscalls, types and resources
// from textual descriptions.
package compiler

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

// Overview of compilation process:
// 1. ast.Parse on text file does tokenization and builds AST.
//    This step catches basic syntax errors. AST contains full debug info.
// 2. ExtractConsts as AST returns set of constant identifiers.
//    This step also does verification of include/incdir/define AST nodes.
// 3. User translates constants to values.
// 4. Compile on AST and const values does the rest of the work and returns Prog
//    containing generated sys objects.
// 4.1. assignSyscallNumbers: uses consts to assign syscall numbers.
//      This step also detects unsupported syscalls and discards no longer
//      needed AST nodes (inlcude, define, comments, etc).
// 4.2. patchConsts: patches Int nodes refering to consts with corresponding values.
//      Also detects unsupported syscalls, structs, resources due to missing consts.
// 4.3. check: does extensive semantical checks of AST.
// 4.4. gen: generates sys objects from AST.

// Prog is description compilation result.
type Prog struct {
	// Processed AST (temporal measure, remove later).
	Desc         *ast.Description
	Resources    []*sys.ResourceDesc
	Syscalls     []*sys.Call
	StructFields []*sys.StructFields
	// Set of unsupported syscalls/flags.
	Unsupported map[string]bool
}

// Compile compiles sys description.
func Compile(desc *ast.Description, consts map[string]uint64, eh ast.ErrorHandler) *Prog {
	if eh == nil {
		eh = ast.LoggingHandler
	}
	comp := &compiler{
		desc:        ast.Clone(desc),
		eh:          eh,
		ptrSize:     8, // TODO(dvyukov): must be provided by target
		unsupported: make(map[string]bool),
		resources:   make(map[string]*ast.Resource),
		structs:     make(map[string]*ast.Struct),
		intFlags:    make(map[string]*ast.IntFlags),
		strFlags:    make(map[string]*ast.StrFlags),
		structUses:  make(map[sys.StructKey]*ast.Struct),
	}
	comp.assignSyscallNumbers(consts)
	comp.patchConsts(consts)
	comp.check()
	if comp.errors != 0 {
		return nil
	}
	for _, w := range comp.warnings {
		eh(w.pos, w.msg)
	}
	return &Prog{
		Desc:         comp.desc,
		Resources:    comp.genResources(),
		Syscalls:     comp.genSyscalls(),
		StructFields: comp.genStructFields(),
		Unsupported:  comp.unsupported,
	}
}

type compiler struct {
	desc     *ast.Description
	eh       ast.ErrorHandler
	errors   int
	warnings []warn
	ptrSize  uint64

	unsupported map[string]bool
	resources   map[string]*ast.Resource
	structs     map[string]*ast.Struct
	intFlags    map[string]*ast.IntFlags
	strFlags    map[string]*ast.StrFlags
	structUses  map[sys.StructKey]*ast.Struct
}

type warn struct {
	pos ast.Pos
	msg string
}

func (comp *compiler) error(pos ast.Pos, msg string, args ...interface{}) {
	comp.errors++
	comp.eh(pos, fmt.Sprintf(msg, args...))
}

func (comp *compiler) warning(pos ast.Pos, msg string, args ...interface{}) {
	comp.warnings = append(comp.warnings, warn{pos, fmt.Sprintf(msg, args...)})
}

func (comp *compiler) check() {
	// TODO: check len in syscall arguments referring to parent.
	// TODO: incorrect name is referenced in len type
	// TODO: infinite recursion via struct pointers (e.g. a linked list)
	// TODO: no constructor for a resource

	comp.checkNames()
	comp.checkFields()

	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Resource:
			comp.checkType(n.Base, false, true)
			comp.checkResource(n)
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

func (comp *compiler) checkResource(n *ast.Resource) {
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

func (comp *compiler) checkStruct(n *ast.Struct) {
	if n.IsUnion {
		comp.parseUnionAttrs(n)
	} else {
		comp.parseStructAttrs(n)
	}
}

func (comp *compiler) parseUnionAttrs(n *ast.Struct) (varlen bool) {
	for _, attr := range n.Attrs {
		switch attr.Name {
		case "varlen":
			varlen = true
		default:
			comp.error(attr.Pos, "unknown union %v attribute %v",
				n.Name.Name, attr.Name)
		}
	}
	return
}

func (comp *compiler) parseStructAttrs(n *ast.Struct) (packed bool, align uint64) {
	for _, attr := range n.Attrs {
		switch {
		case attr.Name == "packed":
			packed = true
		case attr.Name == "align_ptr":
			align = comp.ptrSize
		case strings.HasPrefix(attr.Name, "align_"):
			a, err := strconv.ParseUint(attr.Name[6:], 10, 64)
			if err != nil {
				comp.error(attr.Pos, "bad struct %v alignment %v",
					n.Name.Name, attr.Name[6:])
				continue
			}
			if a&(a-1) != 0 || a == 0 || a > 1<<30 {
				comp.error(attr.Pos, "bad struct %v alignment %v (must be a sane power of 2)",
					n.Name.Name, a)
			}
			align = a
		default:
			comp.error(attr.Pos, "unknown struct %v attribute %v",
				n.Name.Name, attr.Name)
		}
	}
	return
}

func (comp *compiler) getTypeDesc(t *ast.Type) *typeDesc {
	if desc := builtinTypes[t.Ident]; desc != nil {
		return desc
	}
	if comp.resources[t.Ident] != nil {
		return typeResource
	}
	if comp.structs[t.Ident] != nil {
		return typeStruct
	}
	return nil
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

func (comp *compiler) getArgsBase(t *ast.Type, field string, dir sys.Dir, isArg bool) (
	*typeDesc, []*ast.Type, sys.IntTypeCommon) {
	desc := comp.getTypeDesc(t)
	args, opt := removeOpt(t)
	com := genCommon(t.Ident, field, dir, opt)
	base := genIntCommon(com, comp.ptrSize, 0, false)
	if !isArg && desc.NeedBase {
		baseType := args[len(args)-1]
		args = args[:len(args)-1]
		base = typeInt.Gen(comp, baseType, nil, base).(*sys.IntType).IntTypeCommon
	}
	return desc, args, base
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

func removeOpt(t *ast.Type) ([]*ast.Type, bool) {
	args := t.Args
	if len(args) != 0 && args[len(args)-1].Ident == "opt" {
		return args[:len(args)-1], true
	}
	return args, false
}

func (comp *compiler) parseIntType(name string) (size uint64, bigEndian bool) {
	be := strings.HasSuffix(name, "be")
	if be {
		name = name[:len(name)-len("be")]
	}
	size = comp.ptrSize
	if name != "intptr" {
		size, _ = strconv.ParseUint(name[3:], 10, 64)
		size /= 8
	}
	return size, be
}

func toArray(m map[string]bool) []string {
	delete(m, "")
	var res []string
	for v := range m {
		if v != "" {
			res = append(res, v)
		}
	}
	sort.Strings(res)
	return res
}

func arrayContains(a []string, v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}
