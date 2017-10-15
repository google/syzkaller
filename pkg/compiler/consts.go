// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
)

type ConstInfo struct {
	Consts   []string
	Includes []string
	Incdirs  []string
	Defines  map[string]string
}

// ExtractConsts returns list of literal constants and other info required const value extraction.
func ExtractConsts(desc *ast.Description, target *targets.Target, eh0 ast.ErrorHandler) *ConstInfo {
	errors := 0
	eh := func(pos ast.Pos, msg string, args ...interface{}) {
		errors++
		msg = fmt.Sprintf(msg, args...)
		if eh0 != nil {
			eh0(pos, msg)
		} else {
			ast.LoggingHandler(pos, msg)
		}
	}
	info := &ConstInfo{
		Defines: make(map[string]string),
	}
	includeMap := make(map[string]bool)
	incdirMap := make(map[string]bool)
	constMap := make(map[string]bool)

	ast.Walk(desc, func(n1 ast.Node) {
		switch n := n1.(type) {
		case *ast.Include:
			file := n.File.Value
			if includeMap[file] {
				eh(n.Pos, "duplicate include %q", file)
			}
			includeMap[file] = true
			info.Includes = append(info.Includes, file)
		case *ast.Incdir:
			dir := n.Dir.Value
			if incdirMap[dir] {
				eh(n.Pos, "duplicate incdir %q", dir)
			}
			incdirMap[dir] = true
			info.Incdirs = append(info.Incdirs, dir)
		case *ast.Define:
			v := fmt.Sprint(n.Value.Value)
			switch {
			case n.Value.CExpr != "":
				v = n.Value.CExpr
			case n.Value.Ident != "":
				v = n.Value.Ident
			}
			name := n.Name.Name
			if info.Defines[name] != "" {
				eh(n.Pos, "duplicate define %v", name)
			}
			info.Defines[name] = v
			constMap[name] = true
		case *ast.Call:
			if target.SyscallNumbers && !strings.HasPrefix(n.CallName, "syz_") {
				constMap[target.SyscallPrefix+n.CallName] = true
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

	if errors != 0 {
		return nil
	}
	info.Consts = toArray(constMap)
	return info
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
			if !comp.target.SyscallNumbers {
				top = append(top, decl)
				continue
			}
			// Lookup in consts.
			str := comp.target.SyscallPrefix + c.CallName
			nr, ok := consts[str]
			top = append(top, decl)
			if ok {
				c.NR = nr
				continue
			}
			c.NR = ^uint64(0) // mark as unused to not generate it
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
			// Potentially we still can get, say, a bad int range error
			// due to the 0 const value.
			pos, typ, name := decl.Info()
			if id := typ + " " + name; !comp.unsupported[id] {
				comp.unsupported[id] = true
				comp.warning(pos, "unsupported %v: %v due to missing const %v",
					typ, name, missing)
			}
			// We have to keep partially broken resources and structs,
			// because otherwise their usages will error.
			top = append(top, decl)
			if c, ok := decl.(*ast.Call); ok {
				c.NR = ^uint64(0) // mark as unused to not generate it
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
	// TODO: see if we can extract this info from typeDesc/typeArg.
	if n.Ident == "const" && len(n.Args) > 0 {
		return n.Args[0]
	}
	if n.Ident == "array" && len(n.Args) > 1 && n.Args[1].Ident != "opt" {
		return n.Args[1]
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

func SerializeConsts(consts map[string]uint64) []byte {
	type nameValuePair struct {
		name string
		val  uint64
	}
	var nv []nameValuePair
	for k, v := range consts {
		nv = append(nv, nameValuePair{k, v})
	}
	sort.Slice(nv, func(i, j int) bool {
		return nv[i].name < nv[j].name
	})

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# AUTOGENERATED FILE\n")
	for _, x := range nv {
		fmt.Fprintf(buf, "%v = %v\n", x.name, x.val)
	}
	return buf.Bytes()
}

func DeserializeConsts(data []byte, file string, eh ast.ErrorHandler) map[string]uint64 {
	consts := make(map[string]uint64)
	pos := ast.Pos{
		File: file,
		Line: 1,
	}
	ok := true
	s := bufio.NewScanner(bytes.NewReader(data))
	for ; s.Scan(); pos.Line++ {
		line := s.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq == -1 {
			eh(pos, "expect '='")
			ok = false
			continue
		}
		name := strings.TrimSpace(line[:eq])
		val, err := strconv.ParseUint(strings.TrimSpace(line[eq+1:]), 0, 64)
		if err != nil {
			eh(pos, fmt.Sprintf("failed to parse int: %v", err))
			ok = false
			continue
		}
		if _, ok := consts[name]; ok {
			eh(pos, fmt.Sprintf("duplicate const %q", name))
			ok = false
			continue
		}
		consts[name] = val
	}
	if err := s.Err(); err != nil {
		eh(pos, fmt.Sprintf("failed to parse: %v", err))
		ok = false
	}
	if !ok {
		return nil
	}
	return consts
}

func DeserializeConstsGlob(glob string, eh ast.ErrorHandler) map[string]uint64 {
	if eh == nil {
		eh = ast.LoggingHandler
	}
	files, err := filepath.Glob(glob)
	if err != nil {
		eh(ast.Pos{}, fmt.Sprintf("failed to find const files: %v", err))
		return nil
	}
	if len(files) == 0 {
		eh(ast.Pos{}, fmt.Sprintf("no const files matched by glob %q", glob))
		return nil
	}
	consts := make(map[string]uint64)
	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			eh(ast.Pos{}, fmt.Sprintf("failed to read const file: %v", err))
			return nil
		}
		consts1 := DeserializeConsts(data, filepath.Base(f), eh)
		if consts1 == nil {
			consts = nil
		}
		if consts != nil {
			for n, v := range consts1 {
				if old, ok := consts[n]; ok && old != v {
					eh(ast.Pos{}, fmt.Sprintf(
						"different values for const %q: %v vs %v", n, v, old))
					return nil
				}
				consts[n] = v
			}
		}
	}
	return consts
}
