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
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type ConstInfo struct {
	Consts   []string
	Includes []string
	Incdirs  []string
	Defines  map[string]string
}

func ExtractConsts(desc *ast.Description, target *targets.Target, eh ast.ErrorHandler) map[string]*ConstInfo {
	res := Compile(desc, nil, target, eh)
	if res == nil {
		return nil
	}
	return res.fileConsts
}

// extractConsts returns list of literal constants and other info required for const value extraction.
func (comp *compiler) extractConsts() map[string]*ConstInfo {
	infos := make(map[string]*constInfo)
	for _, decl := range comp.desc.Nodes {
		pos, _, _ := decl.Info()
		info := getConstInfo(infos, pos)
		switch n := decl.(type) {
		case *ast.Include:
			info.includeArray = append(info.includeArray, n.File.Value)
		case *ast.Incdir:
			info.incdirArray = append(info.incdirArray, n.Dir.Value)
		case *ast.Define:
			v := fmt.Sprint(n.Value.Value)
			switch {
			case n.Value.CExpr != "":
				v = n.Value.CExpr
			case n.Value.Ident != "":
				v = n.Value.Ident
			}
			name := n.Name.Name
			info.defines[name] = v
			info.consts[name] = true
		case *ast.Call:
			if comp.target.SyscallNumbers && !strings.HasPrefix(n.CallName, "syz_") {
				info.consts[comp.target.SyscallPrefix+n.CallName] = true
			}
		}
	}

	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.Call, *ast.Struct, *ast.Resource, *ast.TypeDef:
			comp.foreachType(decl, func(t *ast.Type, desc *typeDesc,
				args []*ast.Type, _ prog.IntTypeCommon) {
				for i, arg := range args {
					if desc.Args[i].Type.Kind == kindInt {
						if arg.Ident != "" {
							info := getConstInfo(infos, arg.Pos)
							info.consts[arg.Ident] = true
						}
						for _, col := range arg.Colon {
							if col.Ident != "" {
								info := getConstInfo(infos, col.Pos)
								info.consts[col.Ident] = true
							}
						}
					}
				}
			})
		}
	}

	for _, decl := range comp.desc.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			for _, attr := range n.Attrs {
				if attr.Ident == "size" {
					info := getConstInfo(infos, attr.Pos)
					info.consts[attr.Args[0].Ident] = true
				}
			}
		}
	}

	comp.desc.Walk(ast.Recursive(func(n0 ast.Node) {
		if n, ok := n0.(*ast.Int); ok {
			info := getConstInfo(infos, n.Pos)
			info.consts[n.Ident] = true
		}
	}))

	return convertConstInfo(infos)
}

type constInfo struct {
	consts       map[string]bool
	defines      map[string]string
	includeArray []string
	incdirArray  []string
}

func getConstInfo(infos map[string]*constInfo, pos ast.Pos) *constInfo {
	info := infos[pos.File]
	if info == nil {
		info = &constInfo{
			consts:  make(map[string]bool),
			defines: make(map[string]string),
		}
		infos[pos.File] = info
	}
	return info
}

func convertConstInfo(infos map[string]*constInfo) map[string]*ConstInfo {
	res := make(map[string]*ConstInfo)
	for file, info := range infos {
		res[file] = &ConstInfo{
			Consts:   toArray(info.consts),
			Includes: info.includeArray,
			Incdirs:  info.incdirArray,
			Defines:  info.defines,
		}
	}
	return res
}

// assignSyscallNumbers assigns syscall numbers, discards unsupported syscalls.
func (comp *compiler) assignSyscallNumbers(consts map[string]uint64) {
	for _, decl := range comp.desc.Nodes {
		c, ok := decl.(*ast.Call)
		if !ok || strings.HasPrefix(c.CallName, "syz_") {
			continue
		}
		str := comp.target.SyscallPrefix + c.CallName
		nr, ok := consts[str]
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
	}
}

// patchConsts replaces all symbolic consts with their numeric values taken from consts map.
// Updates desc and returns set of unsupported syscalls and flags.
func (comp *compiler) patchConsts(consts map[string]uint64) {
	for _, decl := range comp.desc.Nodes {
		switch decl.(type) {
		case *ast.IntFlags:
			// Unsupported flag values are dropped.
			n := decl.(*ast.IntFlags)
			var values []*ast.Int
			for _, v := range n.Values {
				if comp.patchIntConst(&v.Value, &v.Ident, consts, nil) {
					values = append(values, v)
				}
			}
			n.Values = values
		case *ast.Resource, *ast.Struct, *ast.Call, *ast.TypeDef:
			// Walk whole tree and replace consts in Type's and Int's.
			missing := ""
			comp.foreachType(decl, func(_ *ast.Type, desc *typeDesc,
				args []*ast.Type, _ prog.IntTypeCommon) {
				for i, arg := range args {
					if desc.Args[i].Type.Kind == kindInt {
						comp.patchIntConst(&arg.Value, &arg.Ident, consts, &missing)
						for _, col := range arg.Colon {
							comp.patchIntConst(&col.Value,
								&col.Ident, consts, &missing)
						}
					}
				}
			})
			if n, ok := decl.(*ast.Resource); ok {
				for _, v := range n.Values {
					comp.patchIntConst(&v.Value, &v.Ident, consts, &missing)
				}
			}
			if n, ok := decl.(*ast.Struct); ok {
				for _, attr := range n.Attrs {
					if attr.Ident == "size" {
						sz := attr.Args[0]
						comp.patchIntConst(&sz.Value, &sz.Ident, consts, &missing)
					}
				}
			}
			if missing == "" {
				continue
			}
			// Produce a warning about unsupported syscall/resource/struct.
			// TODO(dvyukov): we should transitively remove everything that
			// depends on unsupported things. Potentially we still can get,
			// say, a bad int range error due to the wrong const value.
			// However, if we have a union where one of the options is
			// arch-specific and does not have a const value, it's probably
			// better to remove just that option. But then if we get to 0
			// options in the union, we still need to remove it entirely.
			pos, typ, name := decl.Info()
			if id := typ + " " + name; !comp.unsupported[id] {
				comp.unsupported[id] = true
				comp.warning(pos, "unsupported %v: %v due to missing const %v",
					typ, name, missing)
			}
			if c, ok := decl.(*ast.Call); ok {
				c.NR = ^uint64(0) // mark as unused to not generate it
			}
		}
	}
}

func (comp *compiler) patchIntConst(val *uint64, id *string, consts map[string]uint64, missing *string) bool {
	if *id == "" {
		return true
	}
	if v, ok := consts[*id]; ok {
		*id = ""
		*val = v
		return true
	}
	if missing != nil && *missing == "" {
		*missing = *id
	}
	// 1 is slightly safer than 0 and allows to work-around e.g. an array size
	// that comes from a const missing on an arch. Also see the TODO in patchConsts.
	*val = 1
	return false
}

func SerializeConsts(consts map[string]uint64, undeclared map[string]bool) []byte {
	type nameValuePair struct {
		declared bool
		name     string
		val      uint64
	}
	var nv []nameValuePair
	for k, v := range consts {
		nv = append(nv, nameValuePair{true, k, v})
	}
	for k := range undeclared {
		nv = append(nv, nameValuePair{false, k, 0})
	}
	sort.Slice(nv, func(i, j int) bool {
		return nv[i].name < nv[j].name
	})

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# AUTOGENERATED FILE\n")
	for _, x := range nv {
		if x.declared {
			fmt.Fprintf(buf, "%v = %v\n", x.name, x.val)
		} else {
			fmt.Fprintf(buf, "# %v is not set\n", x.name)
		}
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
		if _, dup := consts[name]; dup {
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
