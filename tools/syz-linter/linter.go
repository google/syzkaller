// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This is our linter with custom checks for the project.
// See the following tutorial on writing Go analyzers:
// https://disaev.me/p/writing-useful-go-analysis-linter/
// See the following tutorial on adding custom golangci-lint linters:
// https://golangci-lint.run/contributing/new-linters/
// See comments below and testdata/src/lintertest/lintertest.go for the actual checks we do.
// Note: if you change linter logic, you may need to run "rm -rf ~/.cache/golangci-lint".
package main

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

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
				checkCommentSpace(pass, n)
			case *ast.BinaryExpr:
				checkStringLenCompare(pass, n)
			}
			return true
		})
	}
	return nil, nil
}

// checkMulitlineComments warns about C++-style multiline comments.
// We don't use them in the codebase.
func checkMulitlineComments(pass *analysis.Pass, n *ast.Comment) {
	if !strings.HasPrefix(n.Text, "/*") {
		return
	}
	pass.Report(analysis.Diagnostic{
		Pos:     n.Pos(),
		Message: "Use C-style comments // instead of /* */",
	})
}

// checkCommentSpace warns about "//nospace", "// 	tabs and spaces" and similar.
func checkCommentSpace(pass *analysis.Pass, n *ast.Comment) {
	if !strings.HasPrefix(n.Text, "//") ||
		allowedComments.MatchString(n.Text) {
		return
	}
	pass.Report(analysis.Diagnostic{
		Pos:     n.Pos(),
		Message: "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments",
	})
}

var allowedComments = regexp.MustCompile(`^//($|	+[^ 	]| +[^ 	])`)

// checkStringLenCompare checks for string len comparisons with 0.
// E.g.: if len(str) == 0 {} should be if str == "" {}.
func checkStringLenCompare(pass *analysis.Pass, n *ast.BinaryExpr) {
	if n.Op != token.EQL && n.Op != token.NEQ && n.Op != token.LSS &&
		n.Op != token.GTR && n.Op != token.LEQ && n.Op != token.GEQ {
		return
	}
	if isStringLenCall(pass, n.X) && isIntZeroLiteral(n.Y) ||
		isStringLenCall(pass, n.Y) && isIntZeroLiteral(n.X) {
		pass.Report(analysis.Diagnostic{
			Pos:     n.Pos(),
			Message: "Compare string with \"\", don't compare len with 0",
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
	_ = AnalyzerPlugin
}
