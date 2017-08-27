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

	return &Prog{
		Desc:        comp.desc,
		Unsupported: comp.unsupported,
	}
}

type compiler struct {
	desc   *ast.Description
	eh     ast.ErrorHandler
	errors int

	unsupported map[string]bool
}

func (comp *compiler) error(pos ast.Pos, msg string, args ...interface{}) {
	comp.errors++
	comp.warning(pos, msg, args...)
}

func (comp *compiler) warning(pos ast.Pos, msg string, args ...interface{}) {
	comp.eh(pos, fmt.Sprintf(msg, args...))
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
			ast.WalkNode(decl, nil, func(n0, _ ast.Node) {
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
			// Unsupported syscalls are discarded.
			// Unsupported resource/struct lead to compilation error.
			// Fixing that would require removing all uses of the resource/struct.
			pos, typ, name := ast.Pos{}, "", ""
			fn := comp.error
			switch n := decl.(type) {
			case *ast.Call:
				pos, typ, name = n.Pos, "syscall", n.Name.Name
				fn = comp.warning
			case *ast.Resource:
				pos, typ, name = n.Pos, "resource", n.Name.Name
			case *ast.Struct:
				pos, typ, name = n.Pos, "struct", n.Name.Name
			default:
				panic(fmt.Sprintf("unknown type: %#v", decl))
			}
			if id := typ + " " + name; !comp.unsupported[id] {
				comp.unsupported[id] = true
				fn(pos, "unsupported %v: %v due to missing const %v",
					typ, name, missing)
			}
		}
	}
	comp.desc.Nodes = top
}

// ExtractConsts returns list of literal constants and other info required const value extraction.
func ExtractConsts(desc *ast.Description) (consts, includes, incdirs []string, defines map[string]string) {
	constMap := make(map[string]bool)
	defines = make(map[string]string)

	ast.Walk(desc, func(n1, _ ast.Node) {
		switch n := n1.(type) {
		case *ast.Include:
			includes = append(includes, n.File.Value)
		case *ast.Incdir:
			incdirs = append(incdirs, n.Dir.Value)
		case *ast.Define:
			v := fmt.Sprint(n.Value.Value)
			switch {
			case n.Value.CExpr != "":
				v = n.Value.CExpr
			case n.Value.Ident != "":
				v = n.Value.Ident
			}
			defines[n.Name.Name] = v
			constMap[n.Name.Name] = true
		case *ast.Call:
			if !strings.HasPrefix(n.CallName, "syz_") {
				constMap["__NR_"+n.CallName] = true
			}
		case *ast.Type:
			if c := typeConstIdentifier(n); c != nil {
				constMap[c.Ident] = true
				constMap[c.Ident2] = true
			}
		case *ast.Int:
			constMap[n.Ident] = true
		}
	})

	consts = toArray(constMap)
	return
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
