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
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
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

func main() {}

func New(conf any) ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{
		SyzAnalyzer,
		// Some standard analyzers that are not enabled in vet.
		atomicalign.Analyzer,
		copylock.Analyzer,
		deepequalerrors.Analyzer,
		nilness.Analyzer,
		structtag.Analyzer,
	}, nil
}

var SyzAnalyzer = &analysis.Analyzer{
	Name: "lint",
	Doc:  "custom syzkaller project checks",
	Run:  run,
}

func run(p *analysis.Pass) (any, error) {
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
			case *ast.FuncDecl:
				pass.checkFuncArgs(n)
				pass.checkContextArgs(n)
			case *ast.CallExpr:
				pass.checkFlagDefinition(n)
				pass.checkLogErrorFormat(n)
				pass.checkSliceClone(n)
				pass.checkSortUsage(n)
			case *ast.GenDecl:
				pass.checkVarDecl(n)
			case *ast.IfStmt:
				pass.checkIfStmt(n)
			case *ast.AssignStmt:
				pass.checkAssignStmt(n)
			case *ast.InterfaceType:
				pass.checkInterfaceType(n)
			case *ast.BlockStmt:
				pass.checkWhileStyleForLoop(n)
				pass.checkMapKeysExtractionAndSort(n)
			case *ast.ForStmt:
				pass.checkRangeOverIntegers(n)
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

func (pass *Pass) report(pos ast.Node, msg string, args ...any) {
	pass.Report(analysis.Diagnostic{
		Pos:     pos.Pos(),
		Message: fmt.Sprintf(msg, args...),
	})
}

func (pass *Pass) typ(e ast.Expr) string {
	return pass.TypesInfo.Types[e].Type.String()
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
	specialComment    = regexp.MustCompile(`//go:generate|//go:build|//go:embed|//go:linkname|// nolint:`)
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
	return pass.typ(call.Args[0]) == "string"
}

func (pass *Pass) isIntZeroLiteral(n ast.Expr) bool {
	lit, ok := n.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

// checkFuncArgs checks for "func foo(a int, b int)" -> "func foo(a, b int)".
func (pass *Pass) checkFuncArgs(n *ast.FuncDecl) {
	variadic := pass.TypesInfo.ObjectOf(n.Name).(*types.Func).Type().(*types.Signature).Variadic()
	pass.checkFuncArgList(n.Type.Params.List, variadic)
	if n.Type.Results != nil {
		pass.checkFuncArgList(n.Type.Results.List, false)
	}
}

func (pass *Pass) checkFuncArgList(fields []*ast.Field, variadic bool) {
	firstBad := -1
	var prev string
	for i, field := range fields {
		if len(field.Names) == 0 {
			pass.reportFuncArgs(fields, firstBad, i)
			firstBad, prev = -1, ""
			continue
		}
		this := pass.typ(field.Type)
		// For variadic functions the actual type of the last argument is a slice,
		// but we don't want to warn on "a []int, b ...int".
		if variadic && i == len(fields)-1 {
			this = "..." + this
		}
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
	pass.report(fields[first], "Use '%v %v'", names[2:], pass.typ(fields[first].Type))
}

func (pass *Pass) checkContextArgs(n *ast.FuncDecl) {
	if n.Type.Params == nil {
		return
	}
	expectedCtxPos := 0
	if len(n.Type.Params.List) > 0 {
		firstField := n.Type.Params.List[0]
		if strings.HasSuffix(pass.typ(firstField.Type), "*testing.T") {
			expectedCtxPos = 1
		}
	}
	for fieldPos, field := range n.Type.Params.List {
		isContext := pass.typ(field.Type) == "context.Context"
		if isContext {
			if fieldPos != expectedCtxPos {
				if expectedCtxPos == 0 {
					pass.report(field, "Context must be the first argument")
				} else {
					pass.report(field, "Context must be the second argument")
				}
			}
			// Every type group may have a few variables.
			if len(field.Names) > 1 {
				// A few contexts are passed to the function
				// It is very rare. Let's use nolint:syz-linter to opt-out.
				pass.report(field, "multiple Contexts are passed, use nolint:syz-linter")
			}
			if len(field.Names) == 1 {
				name := field.Names[0]
				if name.Name != "ctx" && name.Name != "_" {
					pass.report(name, "Context variable must be named 'ctx' or '_'")
				}
			}
		}
	}
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

// checkSliceClone warns about manual slice cloning using append([]T{}, slice...)
// and suggests using slices.Clone instead.
func (pass *Pass) checkSliceClone(n *ast.CallExpr) {
	fn, ok := n.Fun.(*ast.Ident)
	if !ok || fn.Name != "append" || len(n.Args) != 2 || n.Ellipsis == token.NoPos {
		return
	}
	arg0, ok := n.Args[0].(*ast.CompositeLit)
	if !ok || len(arg0.Elts) != 0 {
		return
	}
	pass.report(n, "Use slices.Clone instead of append")
}

// checkLogErrorFormat warns about log/error messages starting with capital letter or ending with a period.
func (pass *Pass) checkLogErrorFormat(n *ast.CallExpr) {
	arg, newLine, sure := pass.logFormatArg(n)
	if arg == -1 || len(n.Args) <= arg {
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
	case "log.Print", "log.Printf", "log.Fatal", "log.Fatalf", "fmt.Error", "fmt.Errorf", "jp.Logf":
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
	case "t.Errorf", "t.Fatalf":
		return 0, false, true
	case "tool.Failf":
		return 0, false, true
	}
	if fun.Sel.String() == "Logf" {
		return 0, false, true
	}
	return -1, false, false
}

var publicIdentifier = regexp.MustCompile(`^[A-Z][[:alnum:]]+?((\.|[A-Z])[[:alnum:]]+)+ `)

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

func (pass *Pass) checkIfStmt(n *ast.IfStmt) {
	cond, ok := n.Cond.(*ast.BinaryExpr)
	if !ok || len(n.Body.List) != 1 {
		return
	}
	assign, ok := n.Body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 {
		return
	}
	isMin := true
	switch cond.Op {
	case token.GTR, token.GEQ:
	case token.LSS, token.LEQ:
		isMin = false
	default:
		return
	}
	x := pass.nodeString(cond.X)
	y := pass.nodeString(cond.Y)
	lhs := pass.nodeString(assign.Lhs[0])
	rhs := pass.nodeString(assign.Rhs[0])
	switch {
	case x == lhs && y == rhs:
	case x == rhs && y == lhs:
		isMin = !isMin
	default:
		return
	}
	fn := map[bool]string{true: "min", false: "max"}[isMin]
	pass.report(n, "Use %v function instead", fn)
}

func (pass *Pass) nodeString(n ast.Node) string {
	w := new(bytes.Buffer)
	printer.Fprint(w, pass.Fset, n)
	return w.String()
}

// checkAssignStmt warns about loop variables duplication attempts.
// Before go122 loop variables were per-loop, not per-iter.
func (pass *Pass) checkAssignStmt(n *ast.AssignStmt) {
	if len(n.Lhs) != len(n.Rhs) {
		return
	}
	for i, lhs := range n.Lhs {
		lIdent, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		rIdent, ok := n.Rhs[i].(*ast.Ident)
		if !ok {
			return
		}
		if lIdent.Name != rIdent.Name {
			return
		}
	}
	pass.report(n, "Don't duplicate loop variables. They are per-iter (not per-loop) since go122.")
}

func (pass *Pass) checkInterfaceType(n *ast.InterfaceType) {
	if len(n.Methods.List) == 0 {
		pass.report(n, "Use any instead of interface{}")
	}
}

// checkSortUsage flags usages of sort.Strings and sort.Slice that can be replaced with slices package.
func (pass *Pass) checkSortUsage(n *ast.CallExpr) {
	// Check if the function call is a selector expression (e.g., package.Function).
	sel, ok := n.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	// Check if the package name is "sort".
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "sort" {
		return
	}
	switch sel.Sel.Name {
	case "Strings":
		// Suggest slices.Sort for sort.Strings.
		pass.report(n, "Use slices.Sort instead of sort.Strings")
	case "Slice":
		// For sort.Slice, we expect at least 2 arguments: the slice and the less function.
		if len(n.Args) < 2 {
			return
		}
		// Check if the second argument is a function literal (anonymous function).
		fn, ok := n.Args[1].(*ast.FuncLit)
		if !ok {
			return
		}
		// We only look for simple one-line functions.
		if len(fn.Body.List) != 1 {
			return
		}
		// Check if the single statement is a return statement.
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return
		}
		// Check if the return value is a binary expression (e.g., a < b or a > b).
		bin, ok := ret.Results[0].(*ast.BinaryExpr)
		if !ok || (bin.Op != token.LSS && bin.Op != token.GTR) {
			return // We only look for '<' or '>' operators for simplicity.
		}

		// Suggest alternatives for any simple one-line predicate using '<'.
		pass.report(n, "Use slices.Sort or slices.SortFunc instead of sort.Slice with a simple predicate")
	}
}

// checkRangeOverIntegers warns about traditional for loops that can be replaced with range over integers.
func (pass *Pass) checkRangeOverIntegers(n *ast.ForStmt) {
	if n.Init == nil || n.Cond == nil || n.Post == nil {
		return
	}

	// Check Init: i := 0 or i = 0
	assign, ok := n.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return
	}
	if !pass.isIntZeroLiteral(assign.Rhs[0]) {
		return
	}

	// Check Cond: i < N
	bin, ok := n.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.LSS {
		return
	}
	condIdent, ok := bin.X.(*ast.Ident)
	if !ok || condIdent.Name != ident.Name {
		return
	}

	// Check Post: i++
	inc, ok := n.Post.(*ast.IncDecStmt)
	if !ok || inc.Tok != token.INC {
		return
	}
	postIdent, ok := inc.X.(*ast.Ident)
	if !ok || postIdent.Name != ident.Name {
		return
	}

	pass.report(n, "Use range over integer instead of traditional for loop")
}

// checkWhileStyleForLoop warns about while-style loops with external counter initialization
// that can be replaced with a traditional for loop header to limit scope.
func (pass *Pass) checkWhileStyleForLoop(n *ast.BlockStmt) {
	for i := range len(n.List) - 1 {
		assign, ok := n.List[i].(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || !pass.isIntZeroLiteral(assign.Rhs[0]) {
			continue
		}
		forStmt, ok := n.List[i+1].(*ast.ForStmt)
		if !ok || forStmt.Init != nil || forStmt.Post != nil || forStmt.Cond == nil {
			continue
		}
		bin, ok := forStmt.Cond.(*ast.BinaryExpr)
		if !ok || bin.Op != token.LSS {
			continue
		}
		condIdent, ok := bin.X.(*ast.Ident)
		if !ok || condIdent.Name != ident.Name {
			continue
		}
		pass.report(forStmt, "Consider using for %v := 0; %v < ...; { to scope the loop variable", ident.Name, ident.Name)
	}
}

// checkMapKeysExtractionAndSort warns about manual loops extracting map keys followed by sort.
func (pass *Pass) checkMapKeysExtractionAndSort(n *ast.BlockStmt) {
	for i := range len(n.List) - 1 {
		rangeStmt, ok := n.List[i].(*ast.RangeStmt)
		if !ok {
			continue
		}
		sliceIdent, ok := pass.isMapKeysExtraction(rangeStmt)
		if !ok {
			continue
		}
		nextStmt := n.List[i+1]
		if pass.isSortCall(nextStmt, sliceIdent) {
			pass.report(rangeStmt, "Use maps.Keys and slices.Sort instead of a manual loop")
		}
	}
}

func (pass *Pass) isMapKeysExtraction(n *ast.RangeStmt) (*ast.Ident, bool) {
	if n.Value != nil || len(n.Body.List) != 1 {
		return nil, false
	}
	assign, ok := n.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil, false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return nil, false
	}
	fn, ok := call.Fun.(*ast.Ident)
	if !ok || fn.Name != "append" {
		return nil, false
	}
	keyIdent, ok := n.Key.(*ast.Ident)
	if !ok {
		return nil, false
	}
	argIdent, ok := call.Args[1].(*ast.Ident)
	if !ok || argIdent.Name != keyIdent.Name {
		return nil, false
	}
	lhsIdent, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, false
	}
	appendArgIdent, ok := call.Args[0].(*ast.Ident)
	if !ok || appendArgIdent.Name != lhsIdent.Name {
		return nil, false
	}
	if typ := pass.TypesInfo.Types[n.X].Type; typ != nil {
		if _, isMap := typ.Underlying().(*types.Map); !isMap {
			return nil, false
		}
	}
	return lhsIdent, true
}

func (pass *Pass) isSortCall(n ast.Stmt, sliceIdent *ast.Ident) bool {
	exprStmt, ok := n.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	argIdent, ok := call.Args[0].(*ast.Ident)
	if !ok || argIdent.Name != sliceIdent.Name {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	xIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if xIdent.Name == "slices" && sel.Sel.Name == "Sort" {
		return true
	}
	if xIdent.Name == "sort" && sel.Sel.Name == "Strings" {
		return true
	}
	return false
}
