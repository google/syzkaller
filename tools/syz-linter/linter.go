// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// https://golangci-lint.run/contributing/new-linters/

package main

import (
	"go/ast"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// nolint
var AnalyzerPlugin analyzerPlugin

type analyzerPlugin struct{}

func (*analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		SyzAnalyzer,
	}
}

var SyzAnalyzer = &analysis.Analyzer{
	Name: "lint",
	Doc:  "custom syzkaller project checks",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Comment:
				checkMulitlineComments(pass, n)
			case *ast.BinaryExpr:
				checkStringLenCompare(pass, n)
			}
			return true
		})
	}
	return nil, nil
}

func checkMulitlineComments(pass *analysis.Pass, n *ast.Comment) {
	if !strings.HasPrefix(n.Text, "/*") {
		return
	}
	pass.Report(analysis.Diagnostic{
		Pos:     n.Pos(),
		Message: "Use C-style comments // instead of /* */",
	})
}

// checkStringLenCompare checks for string len comparisons with 0.
// E.g.: if len(str) == 0 {}.
func checkStringLenCompare(pass *analysis.Pass, n *ast.BinaryExpr) {
	if n.Op != token.EQL && n.Op != token.NEQ && n.Op != token.LSS &&
		n.Op != token.GTR && n.Op != token.LEQ && n.Op != token.GEQ {
		return
	}
	if isStringLenCall(pass, n.X) && isIntZeroLiteral(n.Y) ||
		isStringLenCall(pass, n.Y) && isIntZeroLiteral(n.X) {
		pass.Report(analysis.Diagnostic{
			Pos:     n.Pos(),
			Message: "compare string with \"\", don't compare len with 0",
		})
	}
}

func isStringLenCall(pass *analysis.Pass, n ast.Expr) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	fun, ok := call.Fun.(*ast.Ident)
	if !ok || fun.Name != "len" {
		return false
	}
	return pass.TypesInfo.Types[call.Args[0]].Type.String() == "string"
}

func isIntZeroLiteral(n ast.Expr) bool {
	lit, ok := n.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

func main() {
}
