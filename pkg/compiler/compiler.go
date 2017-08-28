// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

// Prog is description compilation result.
type Prog struct {
	// Processed AST (temporal measure, remove later).
	Desc      *ast.Description
	Resources []*sys.ResourceDesc
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
		unsupported: make(map[string]bool),
	}

	comp.assignSyscallNumbers(consts)
	comp.patchConsts(consts)
	if comp.errors != 0 {
		return nil
	}

	comp.check()

	if comp.errors != 0 {
		return nil
	}
	for _, w := range comp.warnings {
		eh(w.pos, w.msg)
	}
	return &Prog{
		Desc:        comp.desc,
		Unsupported: comp.unsupported,
	}
}

type compiler struct {
	desc     *ast.Description
	eh       ast.ErrorHandler
	errors   int
	warnings []warn

	unsupported map[string]bool

	udt   map[string]ast.Node // structs, unions and resources
	flags map[string]ast.Node // int and string flags
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

type typeDesc struct {
	Names        []string
	CanBeArg     bool
	NeedBase     bool
	AllowColon   bool
	ResourceBase bool
	Args         []*typeDesc
}

var (
	typeDir = &typeDesc{
		Names: []string{"in", "out", "inout"},
	}

	topTypes = []*typeDesc{
		&typeDesc{
			Names: []string{"int8", "int16", "int32", "int64",
				"int16be", "int32be", "int64be", "intptr"},
			CanBeArg:     true,
			AllowColon:   true,
			ResourceBase: true,
		},
		&typeDesc{
			Names:    []string{"fileoff"},
			CanBeArg: true,
			NeedBase: true,
		},
		&typeDesc{
			Names:    []string{"buffer"},
			CanBeArg: true,
			Args:     []*typeDesc{typeDir},
		},
		&typeDesc{
			Names: []string{"string"},
			//Args:     []*typeDesc{typeDir},
		},
	}

	builtinTypes = make(map[string]bool)
)

func init() {
	for _, desc := range topTypes {
		for _, name := range desc.Names {
			if builtinTypes[name] {
				panic(fmt.Sprintf("duplicate builtin type %q", name))
			}
			builtinTypes[name] = true
		}
	}
}

var typeCheck bool

func (comp *compiler) check() {
	// TODO: check len in syscall arguments referring to parent.
	// TODO: incorrect name is referenced in len type
	// TODO: infinite recursion via struct pointers (e.g. a linked list)
	// TODO: no constructor for a resource
	// TODO: typo of intour instead of inout

	comp.checkNames()
	comp.checkFields()

	if typeCheck {
		for _, decl := range comp.desc.Nodes {
			switch n := decl.(type) {
			case *ast.Resource:
				comp.checkType(n.Base, false, true)
			case *ast.Struct:
				for _, f := range n.Fields {
					comp.checkType(f.Type, false, false)
				}
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
}

func (comp *compiler) checkNames() {
	comp.udt = make(map[string]ast.Node)
	comp.flags = make(map[string]ast.Node)
	calls := make(map[string]*ast.Call)
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Resource, *ast.Struct:
			pos, typ, name := decl.Info()
			if builtinTypes[name] {
				comp.error(pos, "%v name %v conflicts with builtin type", typ, name)
				continue
			}
			if prev := comp.udt[name]; prev != nil {
				pos1, typ1, _ := prev.Info()
				comp.error(pos, "type %v redeclared, previously declared as %v at %v",
					name, typ1, pos1)
				continue
			}
			comp.udt[name] = decl
		case *ast.IntFlags, *ast.StrFlags:
			pos, typ, name := decl.Info()
			if prev := comp.flags[name]; prev != nil {
				pos1, typ1, _ := prev.Info()
				comp.error(pos, "%v %v redeclared, previously declared as %v at %v",
					typ, name, typ1, pos1)
				continue
			}
			comp.flags[name] = decl
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

func (comp *compiler) checkType(t *ast.Type, isArg, isResourceBase bool) {
	if t.String != "" {
		comp.error(t.Pos, "unexpected string %q, expecting type", t.String)
		return
	}
	if t.Ident == "" {
		comp.error(t.Pos, "unexpected integer %v, expecting type", t.Value)
		return
	}
	var desc *typeDesc
	for _, desc1 := range topTypes {
		for _, name := range desc1.Names {
			if name == t.Ident {
				desc = desc1
				break
			}
		}
	}
	if desc == nil {
		comp.error(t.Pos, "unknown type %q", t.Ident)
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
}

// assignSyscallNumbers assigns syscall numbers, discards unsupported syscalls
// and removes no longer irrelevant nodes from the tree (comments, new lines, etc).
func (comp *compiler) assignSyscallNumbers(consts map[string]uint64) {
	// Pseudo syscalls starting from syz_ are assigned numbers starting from syzbase.
	// Note: the numbers must be stable (not depend on file reading order, etc),
	// so we have to do it in 2 passes.
	const syzbase = 1000000
	syzcalls := make(map[string]bool)
	for _, decl := range comp.desc.Nodes {
		c, ok := decl.(*ast.Call)
		if !ok {
			continue
		}
		if strings.HasPrefix(c.CallName, "syz_") {
			syzcalls[c.CallName] = true
		}
	}
	syznr := make(map[string]uint64)
	for i, name := range toArray(syzcalls) {
		syznr[name] = syzbase + uint64(i)
	}

	var top []ast.Node
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Call:
			c := decl.(*ast.Call)
			if strings.HasPrefix(c.CallName, "syz_") {
				c.NR = syznr[c.CallName]
				top = append(top, decl)
				continue
			}
			// Lookup in consts.
			str := "__NR_" + c.CallName
			nr, ok := consts[str]
			if ok {
				c.NR = nr
				top = append(top, decl)
				continue
			}
			name := "syscall " + c.CallName
			if !comp.unsupported[name] {
				comp.unsupported[name] = true
				comp.warning(c.Pos, "unsupported syscall: %v due to missing const %v",
					c.CallName, str)
			}
		case *ast.IntFlags, *ast.Resource, *ast.Struct, *ast.StrFlags:
			top = append(top, decl)
		case *ast.NewLine, *ast.Comment, *ast.Include, *ast.Incdir, *ast.Define:
			// These are not needed anymore.
		default:
			panic(fmt.Sprintf("unknown node type: %#v", decl))
		}
	}
	comp.desc.Nodes = top
}

// patchConsts replaces all symbolic consts with their numeric values taken from consts map.
// Updates desc and returns set of unsupported syscalls and flags.
// After this pass consts are not needed for compilation.
func (comp *compiler) patchConsts(consts map[string]uint64) {
	var top []ast.Node
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.IntFlags:
			// Unsupported flag values are dropped.
			n := decl.(*ast.IntFlags)
			var values []*ast.Int
			for _, v := range n.Values {
				if comp.patchIntConst(v.Pos, &v.Value, &v.Ident, consts, nil) {
					values = append(values, v)
				}
			}
			n.Values = values
			top = append(top, n)
		case *ast.StrFlags:
			top = append(top, decl)
		case *ast.Resource, *ast.Struct, *ast.Call:
			// Walk whole tree and replace consts in Int's and Type's.
			missing := ""
			ast.WalkNode(decl, func(n0 ast.Node) {
				switch n := n0.(type) {
				case *ast.Int:
					comp.patchIntConst(n.Pos, &n.Value, &n.Ident, consts, &missing)
				case *ast.Type:
					if c := typeConstIdentifier(n); c != nil {
						comp.patchIntConst(c.Pos, &c.Value, &c.Ident,
							consts, &missing)
						if c.HasColon {
							comp.patchIntConst(c.Pos2, &c.Value2, &c.Ident2,
								consts, &missing)
						}
					}
				}
			})
			if missing == "" {
				top = append(top, decl)
				continue
			}
			// Produce a warning about unsupported syscall/resource/struct.
			// TODO(dvyukov): we should transitively remove everything that
			// depends on unsupported things.
			pos, typ, name := decl.Info()
			if id := typ + " " + name; !comp.unsupported[id] {
				comp.unsupported[id] = true
				comp.warning(pos, "unsupported %v: %v due to missing const %v",
					typ, name, missing)
			}
			// We have to keep partially broken resources and structs,
			// because otherwise their usages will error.
			if _, ok := decl.(*ast.Call); !ok {
				top = append(top, decl)
			}
		}
	}
	comp.desc.Nodes = top
}

func (comp *compiler) patchIntConst(pos ast.Pos, val *uint64, id *string,
	consts map[string]uint64, missing *string) bool {
	if *id == "" {
		return true
	}
	v, ok := consts[*id]
	if !ok {
		name := "const " + *id
		if !comp.unsupported[name] {
			comp.unsupported[name] = true
			comp.warning(pos, "unsupported const: %v", *id)
		}
		if missing != nil && *missing == "" {
			*missing = *id
		}
	}
	*val = v
	*id = ""
	return ok
}

// typeConstIdentifier returns type arg that is an integer constant (subject for const patching), if any.
func typeConstIdentifier(n *ast.Type) *ast.Type {
	if n.Ident == "const" && len(n.Args) > 0 {
		return n.Args[0]
	}
	if n.Ident == "array" && len(n.Args) > 1 && n.Args[1].Ident != "opt" {
		return n.Args[1]
	}
	if n.Ident == "vma" && len(n.Args) > 0 && n.Args[0].Ident != "opt" {
		return n.Args[0]
	}
	if n.Ident == "vma" && len(n.Args) > 0 && n.Args[0].Ident != "opt" {
		return n.Args[0]
	}
	if n.Ident == "string" && len(n.Args) > 1 && n.Args[1].Ident != "opt" {
		return n.Args[1]
	}
	if n.Ident == "csum" && len(n.Args) > 2 && n.Args[1].Ident == "pseudo" {
		return n.Args[2]
	}
	switch n.Ident {
	case "int8", "int16", "int16be", "int32", "int32be", "int64", "int64be", "intptr":
		if len(n.Args) > 0 && n.Args[0].Ident != "opt" {
			return n.Args[0]
		}
	}
	return nil
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
