// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type indexFile struct {
	Indexes []struct {
		Kind       string `yaml:"kind"`
		Ancestor   bool   `yaml:"ancestor"`
		Properties []struct {
			Name string `yaml:"name"`
		} `yaml:"properties"`
	} `yaml:"indexes"`
}

type parsedQuery struct {
	file          string
	line          int
	kind          string
	ancestor      bool
	hasInequality bool
	props         []string
	orders        int
	filters       int
}

func TestDatastoreIndexes(t *testing.T) {
	data, err := os.ReadFile("index.yaml")
	require.NoError(t, err)

	var cfg indexFile
	err = yaml.Unmarshal(data, &cfg)
	require.NoError(t, err)

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)

		ast.Inspect(node, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			for _, query := range extractQueries(fset, file, fn.Body) {
				if !hasMatchingIndex(cfg, query) {
					t.Errorf("%s:%d: query for kind %q (ancestor=%v, props=%v) missing from index.yaml",
						query.file, query.line, query.kind, query.ancestor, query.props)
				}
			}
			return true
		})
	}
}

func extractQueries(fset *token.FileSet, file string, body *ast.BlockStmt) []parsedQuery {
	var res []parsedQuery
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewQuery" || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		q := parsedQuery{
			file: file,
			line: fset.Position(call.Pos()).Line,
			kind: strings.Trim(lit.Value, `"`),
		}

		ast.Inspect(body, func(childNode ast.Node) bool {
			childCall, ok := childNode.(*ast.CallExpr)
			if !ok {
				return true
			}
			methodSel, ok := childCall.Fun.(*ast.SelectorExpr)
			if !ok || !isDerivedFrom(childCall.Fun, call) {
				return true
			}
			switch methodSel.Sel.Name {
			case "Ancestor":
				q.ancestor = true
			case "Filter":
				if len(childCall.Args) >= 1 {
					if arg, ok := childCall.Args[0].(*ast.BasicLit); ok && arg.Kind == token.STRING {
						raw := strings.Trim(arg.Value, `"`)
						prop, op := parseFilterProp(raw)
						if op != "=" {
							q.hasInequality = true
						}
						if prop != "" && !slices.Contains(q.props, prop) {
							q.props = append(q.props, prop)
						}
						q.filters++
					}
				}
			case "Order":
				if len(childCall.Args) >= 1 {
					if arg, ok := childCall.Args[0].(*ast.BasicLit); ok && arg.Kind == token.STRING {
						prop := strings.TrimPrefix(strings.Trim(arg.Value, `"`), "-")
						if prop != "" && !slices.Contains(q.props, prop) {
							q.props = append(q.props, prop)
						}
						q.orders++
					}
				}
			}
			return true
		})

		if queryNeedsIndex(q) {
			res = append(res, q)
		}
		return true
	})
	return res
}

func isDerivedFrom(expr ast.Expr, target *ast.CallExpr) bool {
	for curr := expr; curr != nil; {
		if call, ok := curr.(*ast.CallExpr); ok {
			if call == target {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				curr = sel.X
				continue
			}
		}
		if sel, ok := curr.(*ast.SelectorExpr); ok {
			curr = sel.X
			continue
		}
		break
	}
	return false
}

// parseFilterProp splits a filter string like "Field >=" into property name ("Field") and operator (">=").
// Multi-character operators are listed first so "<=" and ">=" match before "<" and ">".
func parseFilterProp(raw string) (string, string) {
	for _, op := range []string{"<=", ">=", "!=", "=", "<", ">"} {
		if idx := strings.Index(raw, op); idx != -1 {
			return strings.TrimSpace(raw[:idx]), op
		}
	}
	return strings.TrimSpace(raw), "="
}

// queryNeedsIndex returns true if Datastore requires a composite index for q:
// 1. Ancestor filter combined with Order or inequality filter.
// 2. Multiple Order clauses.
// 3. Filter combined with Order on different properties.
// 4. Inequality filter combined with multiple filters.
func queryNeedsIndex(q parsedQuery) bool {
	if q.ancestor && (q.orders > 0 || q.hasInequality) {
		return true
	}
	if q.orders > 1 || (q.filters > 0 && q.orders > 0) {
		return true
	}
	if q.hasInequality && q.filters > 1 {
		return true
	}
	return false
}

func hasMatchingIndex(cfg indexFile, q parsedQuery) bool {
	for _, entry := range cfg.Indexes {
		if entry.Kind != q.kind || (q.ancestor && !entry.Ancestor) {
			continue
		}

		// The leading property of the index must be present in the query's properties.
		// An index starting with an unqueried property (e.g., ReportLen desc, Time desc)
		// cannot serve a query that only queries Time desc.
		if len(entry.Properties) > 0 && !slices.Contains(q.props, entry.Properties[0].Name) {
			continue
		}

		match := true
		for _, p := range q.props {
			if !slices.ContainsFunc(entry.Properties, func(prop struct{ Name string `yaml:"name"` }) bool {
				return prop.Name == p
			}) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
