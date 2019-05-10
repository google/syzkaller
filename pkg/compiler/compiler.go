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
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// Overview of compilation process:
// 1. ast.Parse on text file does tokenization and builds AST.
//    This step catches basic syntax errors. AST contains full debug info.
// 2. ExtractConsts as AST returns set of constant identifiers.
//    This step also does verification of include/incdir/define AST nodes.
// 3. User translates constants to values.
// 4. Compile on AST and const values does the rest of the work and returns Prog
//    containing generated prog objects.
// 4.1. assignSyscallNumbers: uses consts to assign syscall numbers.
//      This step also detects unsupported syscalls and discards no longer
//      needed AST nodes (inlcude, define, comments, etc).
// 4.2. patchConsts: patches Int nodes referring to consts with corresponding values.
//      Also detects unsupported syscalls, structs, resources due to missing consts.
// 4.3. check: does extensive semantical checks of AST.
// 4.4. gen: generates prog objects from AST.

// Prog is description compilation result.
type Prog struct {
	Resources   []*prog.ResourceDesc
	Syscalls    []*prog.Syscall
	StructDescs []*prog.KeyedStruct
	// Set of unsupported syscalls/flags.
	Unsupported map[string]bool
	// Returned if consts was nil.
	fileConsts map[string]*ConstInfo
}

func createCompiler(desc *ast.Description, target *targets.Target, eh ast.ErrorHandler) *compiler {
	if eh == nil {
		eh = ast.LoggingHandler
	}
	comp := &compiler{
		desc:         desc,
		target:       target,
		eh:           eh,
		ptrSize:      target.PtrSize,
		unsupported:  make(map[string]bool),
		resources:    make(map[string]*ast.Resource),
		typedefs:     make(map[string]*ast.TypeDef),
		structs:      make(map[string]*ast.Struct),
		intFlags:     make(map[string]*ast.IntFlags),
		strFlags:     make(map[string]*ast.StrFlags),
		used:         make(map[string]bool),
		usedTypedefs: make(map[string]bool),
		structDescs:  make(map[prog.StructKey]*prog.StructDesc),
		structNodes:  make(map[*prog.StructDesc]*ast.Struct),
		structVarlen: make(map[string]bool),
	}
	for name, n := range builtinTypedefs {
		comp.typedefs[name] = n
		comp.usedTypedefs[name] = true
	}
	for name, n := range builtinStrFlags {
		comp.strFlags[name] = n
	}
	return comp
}

// Compile compiles sys description.
func Compile(desc *ast.Description, consts map[string]uint64, target *targets.Target, eh ast.ErrorHandler) *Prog {
	comp := createCompiler(desc.Clone(), target, eh)
	comp.typecheck()
	// The subsequent, more complex, checks expect basic validity of the tree,
	// in particular corrent number of type arguments. If there were errors,
	// don't proceed to avoid out-of-bounds references to type arguments.
	if comp.errors != 0 {
		return nil
	}
	if consts == nil {
		fileConsts := comp.extractConsts()
		if comp.errors != 0 {
			return nil
		}
		return &Prog{fileConsts: fileConsts}
	}
	if comp.target.SyscallNumbers {
		comp.assignSyscallNumbers(consts)
	}
	comp.patchConsts(consts)
	comp.check()
	if comp.errors != 0 {
		return nil
	}
	for _, w := range comp.warnings {
		eh(w.pos, w.msg)
	}
	syscalls := comp.genSyscalls()
	prg := &Prog{
		Resources:   comp.genResources(),
		Syscalls:    syscalls,
		StructDescs: comp.genStructDescs(syscalls),
		Unsupported: comp.unsupported,
	}
	if comp.errors != 0 {
		return nil
	}
	return prg
}

type compiler struct {
	desc     *ast.Description
	target   *targets.Target
	eh       ast.ErrorHandler
	errors   int
	warnings []warn
	ptrSize  uint64

	unsupported  map[string]bool
	resources    map[string]*ast.Resource
	typedefs     map[string]*ast.TypeDef
	structs      map[string]*ast.Struct
	intFlags     map[string]*ast.IntFlags
	strFlags     map[string]*ast.StrFlags
	used         map[string]bool // contains used structs/resources
	usedTypedefs map[string]bool

	structDescs  map[prog.StructKey]*prog.StructDesc
	structNodes  map[*prog.StructDesc]*ast.Struct
	structVarlen map[string]bool
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

func (comp *compiler) structIsVarlen(name string) bool {
	if varlen, ok := comp.structVarlen[name]; ok {
		return varlen
	}
	s := comp.structs[name]
	if s.IsUnion {
		if varlen, _ := comp.parseUnionAttrs(s); varlen {
			comp.structVarlen[name] = true
			return true
		}
	}
	comp.structVarlen[name] = false // to not hang on recursive types
	varlen := false
	for _, fld := range s.Fields {
		if comp.isVarlen(fld.Type) {
			varlen = true
			break
		}
	}
	comp.structVarlen[name] = varlen
	return varlen
}

func (comp *compiler) parseUnionAttrs(n *ast.Struct) (varlen bool, size uint64) {
	size = sizeUnassigned
	for _, attr := range n.Attrs {
		switch attr.Ident {
		case "varlen":
			if len(attr.Args) != 0 {
				comp.error(attr.Pos, "%v attribute has args", attr.Ident)
			}
			varlen = true
		case "size":
			size = comp.parseSizeAttr(attr)
		default:
			comp.error(attr.Pos, "unknown union %v attribute %v",
				n.Name.Name, attr.Ident)
		}
	}
	return
}

func (comp *compiler) parseStructAttrs(n *ast.Struct) (packed bool, size, align uint64) {
	size = sizeUnassigned
	for _, attr := range n.Attrs {
		switch {
		case attr.Ident == "packed":
			if len(attr.Args) != 0 {
				comp.error(attr.Pos, "%v attribute has args", attr.Ident)
			}
			packed = true
		case attr.Ident == "align_ptr":
			if len(attr.Args) != 0 {
				comp.error(attr.Pos, "%v attribute has args", attr.Ident)
			}
			align = comp.ptrSize
		case strings.HasPrefix(attr.Ident, "align_"):
			if len(attr.Args) != 0 {
				comp.error(attr.Pos, "%v attribute has args", attr.Ident)
			}
			a, err := strconv.ParseUint(attr.Ident[6:], 10, 64)
			if err != nil {
				comp.error(attr.Pos, "bad struct %v alignment %v",
					n.Name.Name, attr.Ident[6:])
				continue
			}
			if a&(a-1) != 0 || a == 0 || a > 1<<30 {
				comp.error(attr.Pos, "bad struct %v alignment %v (must be a sane power of 2)",
					n.Name.Name, a)
			}
			align = a
		case attr.Ident == "size":
			size = comp.parseSizeAttr(attr)
		default:
			comp.error(attr.Pos, "unknown struct %v attribute %v",
				n.Name.Name, attr.Ident)
		}
	}
	return
}

func (comp *compiler) parseSizeAttr(attr *ast.Type) uint64 {
	if len(attr.Args) != 1 {
		comp.error(attr.Pos, "%v attribute is expected to have 1 argument", attr.Ident)
		return sizeUnassigned
	}
	sz := attr.Args[0]
	if unexpected, _, ok := checkTypeKind(sz, kindInt); !ok {
		comp.error(sz.Pos, "unexpected %v, expect int", unexpected)
		return sizeUnassigned
	}
	if len(sz.Colon) != 0 || len(sz.Args) != 0 {
		comp.error(sz.Pos, "size attribute has colon or args")
		return sizeUnassigned
	}
	return sz.Value
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
	if comp.typedefs[t.Ident] != nil {
		return typeTypedef
	}
	return nil
}

func (comp *compiler) getArgsBase(t *ast.Type, field string, dir prog.Dir, isArg bool) (
	*typeDesc, []*ast.Type, prog.IntTypeCommon) {
	desc := comp.getTypeDesc(t)
	if desc == nil {
		panic(fmt.Sprintf("no type desc for %#v", *t))
	}
	args, opt := removeOpt(t)
	com := genCommon(t.Ident, field, sizeUnassigned, dir, opt != nil)
	base := genIntCommon(com, 0, false)
	if desc.NeedBase {
		base.TypeSize = comp.ptrSize
		if !isArg {
			baseType := args[len(args)-1]
			args = args[:len(args)-1]
			base = typeInt.Gen(comp, baseType, nil, base).(*prog.IntType).IntTypeCommon
		}
	}
	return desc, args, base
}

func (comp *compiler) derefPointers(t *ast.Type) (*ast.Type, *typeDesc) {
	for {
		desc := comp.getTypeDesc(t)
		if desc != typePtr {
			return t, desc
		}
		t = t.Args[1]
	}
}

func (comp *compiler) foreachType(n0 ast.Node,
	cb func(*ast.Type, *typeDesc, []*ast.Type, prog.IntTypeCommon)) {
	switch n := n0.(type) {
	case *ast.Call:
		for _, arg := range n.Args {
			comp.foreachSubType(arg.Type, true, cb)
		}
		if n.Ret != nil {
			comp.foreachSubType(n.Ret, true, cb)
		}
	case *ast.Resource:
		comp.foreachSubType(n.Base, false, cb)
	case *ast.Struct:
		for _, f := range n.Fields {
			comp.foreachSubType(f.Type, false, cb)
		}
	case *ast.TypeDef:
		if len(n.Args) == 0 {
			comp.foreachSubType(n.Type, false, cb)
		}
	default:
		panic(fmt.Sprintf("unexpected node %#v", n0))
	}
}

func (comp *compiler) foreachSubType(t *ast.Type, isArg bool,
	cb func(*ast.Type, *typeDesc, []*ast.Type, prog.IntTypeCommon)) {
	desc, args, base := comp.getArgsBase(t, "", prog.DirIn, isArg)
	cb(t, desc, args, base)
	for i, arg := range args {
		if desc.Args[i].Type == typeArgType {
			comp.foreachSubType(arg, desc.Args[i].IsArg, cb)
		}
	}
}

func removeOpt(t *ast.Type) ([]*ast.Type, *ast.Type) {
	args := t.Args
	if last := len(args) - 1; last >= 0 && args[last].Ident == "opt" {
		return args[:last], args[last]
	}
	return args, nil
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
