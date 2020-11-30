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
	"golang.org/x/tools/go/analysis/passes/atomicalign"
	"golang.org/x/tools/go/analysis/passes/copylock"
	"golang.org/x/tools/go/analysis/passes/deepequalerrors"
	"golang.org/x/tools/go/analysis/passes/nilness"
	"golang.org/x/tools/go/analysis/passes/structtag"
)

var AnalyzerPlugin analyzerPlugin

type analyzerPlugin struct{}

func main() {
	_ = AnalyzerPlugin
}

func (*analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		SyzAnalyzer,
		// Some standard analyzers that are not enabled in vet.
		atomicalign.Analyzer,
		copylock.Analyzer,
		deepequalerrors.Analyzer,
		nilness.Analyzer,
		structtag.Analyzer,
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
		stmts := make(map[int]bool)
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return true
			}
			stmts[pass.Fset.Position(n.Pos()).Line] = true
			switch n := n.(type) {
			case *ast.BinaryExpr:
				pass.checkStringLenCompare(n)
			case *ast.FuncType:
				pass.checkFuncArgs(n)
			case *ast.CallExpr:
				pass.checkFlagDefinition(n)
				pass.checkLogErrorFormat(n)
			case *ast.GenDecl:
				pass.checkVarDecl(n)
			}
			return true
		})
		for _, group := range file.Comments {
			for _, comment := range group.List {
				pass.checkComment(comment, stmts, len(group.List) == 1)
			}
		}
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

// checkComment warns about C++-style multiline comments (we don't use them in the codebase)
// and about "//nospace", "// 	tabs and spaces", two spaces after a period, etc.
// See the following sources for some justification:
// https://pep8.org/#comments
// https://nedbatchelder.com/blog/201401/comments_should_be_sentences.html
// https://www.cultofpedagogy.com/two-spaces-after-period
func (pass *Pass) checkComment(n *ast.Comment, stmts map[int]bool, oneline bool) {
	if strings.HasPrefix(n.Text, "/*") {
		pass.report(n, "Use C-style comments // instead of /* */")
		return
	}
	if specialComment.MatchString(n.Text) {
		return
	}
	if !allowedComments.MatchString(n.Text) {
		pass.report(n, "Use either //<one-or-more-spaces>comment or //<one-or-more-tabs>comment format for comments")
		return
	}
	if strings.Contains(n.Text, ".  ") {
		pass.report(n, "Use one space after a period")
		return
	}
	if !oneline || onelineExceptions.MatchString(n.Text) {
		return
	}
	// The following checks are only done for one-line comments,
	// because multi-line comment blocks are harder to understand.
	standalone := !stmts[pass.Fset.Position(n.Pos()).Line]
	if standalone && lowerCaseComment.MatchString(n.Text) {
		pass.report(n, "Standalone comments should be complete sentences"+
			" with first word capitalized and a period at the end")
	}
	if noPeriodComment.MatchString(n.Text) {
		pass.report(n, "Add a period at the end of the comment")
		return
	}
}

var (
	allowedComments   = regexp.MustCompile(`^//($|	+[^ 	]| +[^ 	])`)
	noPeriodComment   = regexp.MustCompile(`^// [A-Z][a-z].+[a-z]$`)
	lowerCaseComment  = regexp.MustCompile(`^// [a-z]+ `)
	onelineExceptions = regexp.MustCompile(`// want \"|http:|https:`)
	specialComment    = regexp.MustCompile(`//go:generate|// nolint:`)
)

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

func (pass *Pass) checkFlagDefinition(n *ast.CallExpr) {
	fun, ok := n.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	switch fmt.Sprintf("%v.%v", fun.X, fun.Sel) {
	case "flag.Bool", "flag.Duration", "flag.Float64", "flag.Int", "flag.Int64",
		"flag.String", "flag.Uint", "flag.Uint64":
	default:
		return
	}
	if name, ok := stringLit(n.Args[0]); ok {
		if name != strings.ToLower(name) {
			pass.report(n, "Don't use Capital letters in flag names")
		}
	}
	if desc, ok := stringLit(n.Args[2]); ok {
		if desc == "" {
			pass.report(n, "Provide flag description")
		} else if last := desc[len(desc)-1]; last == '.' || last == '\n' {
			pass.report(n, "Don't use %q at the end of flag description", last)
		}
		if len(desc) >= 2 && unicode.IsUpper(rune(desc[0])) && unicode.IsLower(rune(desc[1])) {
			pass.report(n, "Don't start flag description with a Capital letter")
		}
	}
}

// checkLogErrorFormat warns about log/error messages starting with capital letter or ending with a period.
func (pass *Pass) checkLogErrorFormat(n *ast.CallExpr) {
	arg, newLine, sure := pass.logFormatArg(n)
	if arg == -1 {
		return
	}
	val, ok := stringLit(n.Args[arg])
	if !ok {
		return
	}
	ln := len(val)
	if ln == 0 {
		pass.report(n, "Don't use empty log/error messages")
		return
	}
	// Some Printf's legitimately don't need \n, so this check is based on a heuristic.
	// Printf's that don't need \n tend to contain % and are short.
	if !sure && ln < 25 && (ln < 10 || strings.Contains(val, "%")) {
		return
	}
	if val[ln-1] == '.' && (ln < 3 || val[ln-2] != '.' || val[ln-3] != '.') {
		pass.report(n, "Don't use period at the end of log/error messages")
	}
	if newLine && val[ln-1] != '\n' {
		pass.report(n, "Add \\n at the end of printed messages")
	}
	if !newLine && val[ln-1] == '\n' {
		pass.report(n, "Don't use \\n at the end of log/error messages")
	}
	if ln >= 2 && unicode.IsUpper(rune(val[0])) && unicode.IsLower(rune(val[1])) &&
		!publicIdentifier.MatchString(val) {
		pass.report(n, "Don't start log/error messages with a Capital letter")
	}
}

func (pass *Pass) logFormatArg(n *ast.CallExpr) (arg int, newLine, sure bool) {
	fun, ok := n.Fun.(*ast.SelectorExpr)
	if !ok {
		return -1, false, false
	}
	switch fmt.Sprintf("%v.%v", fun.X, fun.Sel) {
	case "log.Print", "log.Printf", "log.Fatal", "log.Fatalf", "fmt.Error", "fmt.Errorf":
		return 0, false, true
	case "log.Logf":
		return 1, false, true
	case "fmt.Print", "fmt.Printf":
		return 0, true, false
	case "fmt.Fprint", "fmt.Fprintf":
		if w, ok := n.Args[0].(*ast.SelectorExpr); !ok || fmt.Sprintf("%v.%v", w.X, w.Sel) != "os.Stderr" {
			break
		}
		return 1, true, true
	}
	return -1, false, false
}

var publicIdentifier = regexp.MustCompile(`^[A-Z][[:alnum:]]+(\.[[:alnum:]]+)+ `)

func stringLit(n ast.Node) (string, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	val, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return val, true
}

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
