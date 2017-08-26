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
func Compile(desc0 *ast.Description, consts map[string]uint64, eh ast.ErrorHandler) *Prog {
	if eh == nil {
		eh = ast.LoggingHandler
	}

	desc := ast.Clone(desc0)
	unsup, ok := patchConsts(desc, consts, eh)
	if !ok {
		return nil
	}

	return &Prog{
		Desc:        desc,
		Unsupported: unsup,
	}
}

// patchConsts replaces all symbolic consts with their numeric values taken from consts map.
// Updates desc and returns set of unsupported syscalls and flags.
// After this pass consts are not needed for compilation.
func patchConsts(desc *ast.Description, consts map[string]uint64, eh ast.ErrorHandler) (map[string]bool, bool) {
	broken := false
	unsup := make(map[string]bool)
	var top []ast.Node
	for _, decl := range desc.Nodes {
		switch decl.(type) {
		case *ast.IntFlags:
			// Unsupported flag values are dropped.
			n := decl.(*ast.IntFlags)
			var values []*ast.Int
			for _, v := range n.Values {
				if patchIntConst(v.Pos, &v.Value, &v.Ident, consts, unsup, nil, eh) {
					values = append(values, v)
				}
			}
			n.Values = values
			top = append(top, n)
		case *ast.Resource, *ast.Struct, *ast.Call:
			if c, ok := decl.(*ast.Call); ok {
				// Extract syscall NR.
				str := "__NR_" + c.CallName
				nr, ok := consts[str]
				if !ok {
					if name := "syscall " + c.CallName; !unsup[name] {
						unsup[name] = true
						eh(c.Pos, fmt.Sprintf("unsupported syscall: %v due to missing const %v",
							c.CallName, str))
					}
					continue
				}
				c.NR = nr
			}
			// Walk whole tree and replace consts in Int's and Type's.
			missing := ""
			ast.WalkNode(decl, func(n0 ast.Node) {
				switch n := n0.(type) {
				case *ast.Int:
					patchIntConst(n.Pos, &n.Value, &n.Ident,
						consts, unsup, &missing, eh)
				case *ast.Type:
					if c := typeConstIdentifier(n); c != nil {
						patchIntConst(c.Pos, &c.Value, &c.Ident,
							consts, unsup, &missing, eh)
						if c.HasColon {
							patchIntConst(c.Pos2, &c.Value2, &c.Ident2,
								consts, unsup, &missing, eh)
						}
					}
				}
			})
			if missing == "" {
				top = append(top, decl)
			} else {
				// Produce a warning about unsupported syscall/resource/struct.
				// Unsupported syscalls are discarded.
				// Unsupported resource/struct lead to compilation error.
				// Fixing that would require removing all uses of the resource/struct.
				typ, pos, name, fatal := "", ast.Pos{}, "", false
				switch n := decl.(type) {
				case *ast.Call:
					typ, pos, name, fatal = "syscall", n.Pos, n.Name.Name, false
				case *ast.Resource:
					typ, pos, name, fatal = "resource", n.Pos, n.Name.Name, true
				case *ast.Struct:
					typ, pos, name, fatal = "struct", n.Pos, n.Name.Name, true
				default:
					panic(fmt.Sprintf("unknown type: %#v", decl))
				}
				if id := typ + " " + name; !unsup[id] {
					unsup[id] = true
					eh(pos, fmt.Sprintf("unsupported %v: %v due to missing const %v",
						typ, name, missing))
				}
				if fatal {
					broken = true
				}
			}
		case *ast.StrFlags:
			top = append(top, decl)
		case *ast.NewLine, *ast.Comment, *ast.Include, *ast.Incdir, *ast.Define:
			// These are not needed anymore.
		default:
			panic(fmt.Sprintf("unknown node type: %#v", decl))
		}
	}
	desc.Nodes = top
	return unsup, !broken
}

// ExtractConsts returns list of literal constants and other info required const value extraction.
func ExtractConsts(desc *ast.Description) (consts, includes, incdirs []string, defines map[string]string) {
	constMap := make(map[string]bool)
	defines = make(map[string]string)

	ast.Walk(desc, func(n1 ast.Node) {
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

func patchIntConst(pos ast.Pos, val *uint64, id *string,
	consts map[string]uint64, unsup map[string]bool, missing *string, eh ast.ErrorHandler) bool {
	if *id == "" {
		return true
	}
	v, ok := consts[*id]
	if !ok {
		name := "const " + *id
		if !unsup[name] {
			unsup[name] = true
			eh(pos, fmt.Sprintf("unsupported const: %v", *id))
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
