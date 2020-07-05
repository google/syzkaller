// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This is our linter with custom checks for the project.
// See the following tutorial on writing Go analyzers:
// https://disaev.me/p/writing-useful-go-analysis-linter/
// See the AST reference see:
// https://pkg.go.dev/go/ast
// https://pkg.go.dev/go/token
// https://pkg.go.dev/go/types
// See the following tutorial on adding custom golangci-lint linters:
// https://golangci-lint.run/contributing/new-linters/
// See comments below and testdata/src/lintertest/lintertest.go for the actual checks we do.
// Note: if you change linter logic, you may need to run "rm -rf ~/.cache/golangci-lint".
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

var AnalyzerPlugin analyzerPlugin

type analyzerPlugin struct{}

func main() {
	_ = AnalyzerPlugin
}

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
			case *ast.FuncType:
				checkFuncArgs(pass, n)
			case *ast.CallExpr:
				checkLogErrorFormat(pass, n)
			case *ast.GenDecl:
				checkVarDecl(pass, n)
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

// checkFuncArgs checks for "func foo(a int, b int)" -> "func foo(a, b int)".
func checkFuncArgs(pass *analysis.Pass, n *ast.FuncType) {
	checkFuncArgList(pass, n.Params.List)
	if n.Results != nil {
		checkFuncArgList(pass, n.Results.List)
	}
}

func checkFuncArgList(pass *analysis.Pass, fields []*ast.Field) {
	firstBad := -1
	var prev types.Type
	for i, field := range fields {
		if len(field.Names) == 0 {
			reportFuncArgs(pass, fields, firstBad, i)
			firstBad, prev = -1, nil
			continue
		}
		this := pass.TypesInfo.Types[field.Type].Type
		if prev != this {
			reportFuncArgs(pass, fields, firstBad, i)
			firstBad, prev = -1, this
			continue
		}
		if firstBad == -1 {
			firstBad = i - 1
		}
	}
	reportFuncArgs(pass, fields, firstBad, len(fields))
}

func reportFuncArgs(pass *analysis.Pass, fields []*ast.Field, first, last int) {
	if first == -1 {
		return
	}
	names := ""
	for _, field := range fields[first:last] {
		for _, name := range field.Names {
			names += ", " + name.Name
		}
	}
	pass.Report(analysis.Diagnostic{
		Pos:     fields[first].Pos(),
		Message: fmt.Sprintf("Use '%v %v'", names[2:], fields[first].Type),
	})
}

// checkLogErrorFormat warns about log/error messages starting with capital letter or ending with dot.
func checkLogErrorFormat(pass *analysis.Pass, n *ast.CallExpr) {
	fun, ok := n.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	arg := 0
	switch fmt.Sprintf("%v.%v", fun.X, fun.Sel) {
	case "log.Print", "log.Printf", "log.Fatal", "log.Fatalf", "fmt.Error", "fmt.Errorf":
		arg = 0
	case "log.Logf":
		arg = 1
	default:
		return
	}
	lit, ok := n.Args[arg].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	report := func(msg string) {
		pass.Report(analysis.Diagnostic{Pos: lit.Pos(), Message: msg})
	}
	val, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	ln := len(val)
	if ln == 0 {
		report("Don't use empty log/error messages")
		return
	}
	if val[ln-1] == '.' && (ln < 3 || val[ln-2] != '.' || val[ln-3] != '.') {
		report("Don't use dot at the end of log/error messages")
	}
	if val[ln-1] == '\n' {
		report("Don't use \\n at the end of log/error messages")
	}
	if ln >= 2 && unicode.IsUpper(rune(val[0])) && unicode.IsLower(rune(val[1])) &&
		!publicIdentifier.MatchString(val) {
		report("Don't start log/error messages with a Capital letter")
	}
}

var publicIdentifier = regexp.MustCompile(`^[A-Z][[:alnum:]]+(\.[[:alnum:]]+)+ `)

// checkVarDecl warns about unnecessary long variable declarations "var x type = foo".
func checkVarDecl(pass *analysis.Pass, n *ast.GenDecl) {
	if n.Tok != token.VAR {
		return
	}
	for _, s := range n.Specs {
		spec, ok := s.(*ast.ValueSpec)
		if !ok || spec.Type == nil || len(spec.Values) == 0 || spec.Names[0].Name == "_" {
			continue
		}
		pass.Report(analysis.Diagnostic{
			Pos: n.Pos(),
			Message: "Don't use both var, type and value in variable declarations\n" +
				"Use either \"var x type\" or \"x := val\" or \"x := type(val)\"",
		})
	}
}
