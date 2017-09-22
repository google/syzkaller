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
// 4.2. patchConsts: patches Int nodes refering to consts with corresponding values.
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
}

// Compile compiles sys description.
func Compile(desc *ast.Description, consts map[string]uint64, target *targets.Target, eh ast.ErrorHandler) *Prog {
	if eh == nil {
		eh = ast.LoggingHandler
	}
	comp := &compiler{
		desc:         ast.Clone(desc),
		target:       target,
		eh:           eh,
		ptrSize:      target.PtrSize,
		unsupported:  make(map[string]bool),
		resources:    make(map[string]*ast.Resource),
		structs:      make(map[string]*ast.Struct),
		intFlags:     make(map[string]*ast.IntFlags),
		strFlags:     make(map[string]*ast.StrFlags),
		used:         make(map[string]bool),
		structDescs:  make(map[prog.StructKey]*prog.StructDesc),
		structNodes:  make(map[*prog.StructDesc]*ast.Struct),
		structVarlen: make(map[string]bool),
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
	syscalls := comp.genSyscalls()
	return &Prog{
		Resources:   comp.genResources(),
		Syscalls:    syscalls,
		StructDescs: comp.genStructDescs(syscalls),
		Unsupported: comp.unsupported,
	}
}

type compiler struct {
	desc     *ast.Description
	target   *targets.Target
	eh       ast.ErrorHandler
	errors   int
	warnings []warn
	ptrSize  uint64

	unsupported map[string]bool
	resources   map[string]*ast.Resource
	structs     map[string]*ast.Struct
	intFlags    map[string]*ast.IntFlags
	strFlags    map[string]*ast.StrFlags
	used        map[string]bool // contains used structs/resources

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

func (comp *compiler) getArgsBase(t *ast.Type, field string, dir prog.Dir, isArg bool) (
	*typeDesc, []*ast.Type, prog.IntTypeCommon) {
	desc := comp.getTypeDesc(t)
	args, opt := removeOpt(t)
	size := sizeUnassigned
	com := genCommon(t.Ident, field, size, dir, opt)
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
