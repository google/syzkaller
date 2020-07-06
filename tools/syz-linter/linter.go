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

func run(p *analysis.Pass) (interface{}, error) {
	pass := (*Pass)(p)
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Comment:
				pass.checkMulitlineComments(n)
				pass.checkCommentSpace(n)
			case *ast.BinaryExpr:
				pass.checkStringLenCompare(n)
			case *ast.FuncType:
				pass.checkFuncArgs(n)
			case *ast.CallExpr:
				pass.checkLogErrorFormat(n)
			case *ast.GenDecl:
				pass.checkVarDecl(n)
			}
			return true
		})
	}
	return nil, nil
}

type Pass analysis.Pass

func (pass *Pass) report(pos ast.Node, msg string, args ...interface{}) {
	pass.Report(analysis.Diagnostic{
		Pos:     pos.Pos(),
		Message: fmt.Sprintf(msg, args...),
	})
}

func (pass *Pass) typ(e ast.Expr) types.Type {
	return pass.TypesInfo.Types[e].Type
}

// checkMulitlineComments warns about C++-style multiline comments.
// We don't use them in the codebase.
func (pass *Pass) checkMulitlineComments(n *ast.Comment) {
	if !strings.HasPrefix(n.Text, "/*") {
		return
	}
	pass.report(n, "Use C-style comments // instead of /* */")
}

// checkCommentSpace warns about "//nospace", "// 	tabs and spaces" and similar.
func (pass *Pass) checkCommentSpace(n *ast.Comment) {
	if !strings.HasPrefix(n.Text, "//") ||
		allowedComments.MatchString(n.Text) {
		return
	}
	pass.report(n, "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments")
}

var allowedComments = regexp.MustCompile(`^//($|	+[^ 	]| +[^ 	])`)

// checkStringLenCompare checks for string len comparisons with 0.
// E.g.: if len(str) == 0 {} should be if str == "" {}.
func (pass *Pass) checkStringLenCompare(n *ast.BinaryExpr) {
	if n.Op != token.EQL && n.Op != token.NEQ && n.Op != token.LSS &&
		n.Op != token.GTR && n.Op != token.LEQ && n.Op != token.GEQ {
		return
	}
	if pass.isStringLenCall(n.X) && pass.isIntZeroLiteral(n.Y) ||
		pass.isStringLenCall(n.Y) && pass.isIntZeroLiteral(n.X) {
		pass.report(n, "Compare string with \"\", don't compare len with 0")
	}
}

func (pass *Pass) isStringLenCall(n ast.Expr) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	fun, ok := call.Fun.(*ast.Ident)
	if !ok || fun.Name != "len" {
		return false
	}
	return pass.typ(call.Args[0]).String() == "string"
}

func (pass *Pass) isIntZeroLiteral(n ast.Expr) bool {
	lit, ok := n.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

// checkFuncArgs checks for "func foo(a int, b int)" -> "func foo(a, b int)".
func (pass *Pass) checkFuncArgs(n *ast.FuncType) {
	pass.checkFuncArgList(n.Params.List)
	if n.Results != nil {
		pass.checkFuncArgList(n.Results.List)
	}
}

func (pass *Pass) checkFuncArgList(fields []*ast.Field) {
	firstBad := -1
	var prev types.Type
	for i, field := range fields {
		if len(field.Names) == 0 {
			pass.reportFuncArgs(fields, firstBad, i)
			firstBad, prev = -1, nil
			continue
		}
		this := pass.typ(field.Type)
		if prev != this {
			pass.reportFuncArgs(fields, firstBad, i)
			firstBad, prev = -1, this
			continue
		}
		if firstBad == -1 {
			firstBad = i - 1
		}
	}
	pass.reportFuncArgs(fields, firstBad, len(fields))
}

func (pass *Pass) reportFuncArgs(fields []*ast.Field, first, last int) {
	if first == -1 {
		return
	}
	names := ""
	for _, field := range fields[first:last] {
		for _, name := range field.Names {
			names += ", " + name.Name
		}
	}
	pass.report(fields[first], "Use '%v %v'", names[2:], fields[first].Type)
}

// checkLogErrorFormat warns about log/error messages starting with capital letter or ending with dot.
func (pass *Pass) checkLogErrorFormat(n *ast.CallExpr) {
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
	val, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	ln := len(val)
	if ln == 0 {
		pass.report(lit, "Don't use empty log/error messages")
		return
	}
	if val[ln-1] == '.' && (ln < 3 || val[ln-2] != '.' || val[ln-3] != '.') {
		pass.report(lit, "Don't use dot at the end of log/error messages")
	}
	if val[ln-1] == '\n' {
		pass.report(lit, "Don't use \\n at the end of log/error messages")
	}
	if ln >= 2 && unicode.IsUpper(rune(val[0])) && unicode.IsLower(rune(val[1])) &&
		!publicIdentifier.MatchString(val) {
		pass.report(lit, "Don't start log/error messages with a Capital letter")
	}
}

var publicIdentifier = regexp.MustCompile(`^[A-Z][[:alnum:]]+(\.[[:alnum:]]+)+ `)

// checkVarDecl warns about unnecessary long variable declarations "var x type = foo".
func (pass *Pass) checkVarDecl(n *ast.GenDecl) {
	if n.Tok != token.VAR {
		return
	}
	for _, s := range n.Specs {
		spec, ok := s.(*ast.ValueSpec)
		if !ok || spec.Type == nil || len(spec.Values) == 0 || spec.Names[0].Name == "_" {
			continue
		}
		pass.report(n, "Don't use both var, type and value in variable declarations\n"+
			"Use either \"var x type\" or \"x := val\" or \"x := type(val)\"")
	}
}
