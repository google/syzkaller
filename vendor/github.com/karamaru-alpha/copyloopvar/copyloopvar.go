package copyloopvar

import (
	"fmt"
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var ignoreAlias bool

func NewAnalyzer() *analysis.Analyzer {
	analyzer := &analysis.Analyzer{
		Name: "copyloopvar",
		Doc:  "copyloopvar is a linter detects places where loop variables are copied",
		Run:  run,
		Requires: []*analysis.Analyzer{
			inspect.Analyzer,
		},
	}
	analyzer.Flags.BoolVar(&ignoreAlias, "ignore-alias", false, "ignore aliasing of loop variables")
	return analyzer
}

func run(pass *analysis.Pass) (any, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.RangeStmt)(nil),
		(*ast.ForStmt)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.RangeStmt:
			checkRangeStmt(pass, node)
		case *ast.ForStmt:
			checkForStmt(pass, node)
		}
	})

	return nil, nil
}

func checkRangeStmt(pass *analysis.Pass, rangeStmt *ast.RangeStmt) {
	key, ok := rangeStmt.Key.(*ast.Ident)
	if !ok {
		return
	}
	var value *ast.Ident
	if rangeStmt.Value != nil {
		if value, ok = rangeStmt.Value.(*ast.Ident); !ok {
			return
		}
	}
	for _, stmt := range rangeStmt.Body.List {
		assignStmt, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		if assignStmt.Tok != token.DEFINE {
			continue
		}
		for i, rh := range assignStmt.Rhs {
			right, ok := rh.(*ast.Ident)
			if !ok {
				continue
			}
			if right.Name != key.Name && (value == nil || right.Name != value.Name) {
				continue
			}
			if ignoreAlias {
				left, ok := assignStmt.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if left.Name != right.Name {
					continue
				}
			}
			pass.Report(analysis.Diagnostic{
				Pos:     assignStmt.Pos(),
				Message: fmt.Sprintf(`The copy of the 'for' variable "%s" can be deleted (Go 1.22+)`, right.Name),
			})
		}
	}
}

func checkForStmt(pass *analysis.Pass, forStmt *ast.ForStmt) {
	if forStmt.Init == nil {
		return
	}
	initAssignStmt, ok := forStmt.Init.(*ast.AssignStmt)
	if !ok {
		return
	}
	initVarNameMap := make(map[string]interface{}, len(initAssignStmt.Lhs))
	for _, lh := range initAssignStmt.Lhs {
		if initVar, ok := lh.(*ast.Ident); ok {
			initVarNameMap[initVar.Name] = struct{}{}
		}
	}
	for _, stmt := range forStmt.Body.List {
		assignStmt, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		if assignStmt.Tok != token.DEFINE {
			continue
		}
		for i, rh := range assignStmt.Rhs {
			right, ok := rh.(*ast.Ident)
			if !ok {
				continue
			}
			if _, ok := initVarNameMap[right.Name]; !ok {
				continue
			}
			if ignoreAlias {
				left, ok := assignStmt.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if left.Name != right.Name {
					continue
				}
			}
			pass.Report(analysis.Diagnostic{
				Pos:     assignStmt.Pos(),
				Message: fmt.Sprintf(`The copy of the 'for' variable "%s" can be deleted (Go 1.22+)`, right.Name),
			})
		}
	}
}
