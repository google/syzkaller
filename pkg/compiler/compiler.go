// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
)

// ExtractConsts returns list of literal constants and other info required const value extraction.
func ExtractConsts(top []interface{}) (consts, includes, incdirs []string, defines map[string]string) {
	constMap := make(map[string]bool)
	defines = make(map[string]string)

	ast.Walk(top, func(n1 interface{}) {
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
			if n.Ident == "const" && len(n.Args) > 0 {
				constMap[n.Args[0].Ident] = true
			}
			if n.Ident == "array" && len(n.Args) > 1 {
				constMap[n.Args[1].Ident] = true
			}
		case *ast.Int:
			constMap[n.Ident] = true
		}
	})

	consts = toArray(constMap)
	return
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
