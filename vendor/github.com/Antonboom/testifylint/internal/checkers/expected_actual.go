package checkers

import (
	"go/ast"
	"go/types"
	"regexp"

	"golang.org/x/tools/go/analysis"
)

// DefaultExpectedVarPattern matches variables with "expected" or "wanted" prefix or suffix in the name.
var DefaultExpectedVarPattern = regexp.MustCompile(
	`(^(exp(ected)?|want(ed)?)([A-Z]\w*)?$)|(^(\w*[a-z])?(Exp(ected)?|Want(ed)?)$)`)

// ExpectedActual detects situation like
//
//	assert.NotEqual(t, result, "expected value")
//
// and requires
//
//	assert.NotEqual(t, "expected value", result)
type ExpectedActual struct {
	expVarPattern *regexp.Regexp
}

// NewExpectedActual constructs ExpectedActual checker using DefaultExpectedVarPattern.
func NewExpectedActual() *ExpectedActual {
	return &ExpectedActual{expVarPattern: DefaultExpectedVarPattern}
}

func (ExpectedActual) Name() string { return "expected-actual" }

func (checker *ExpectedActual) SetExpVarPattern(p *regexp.Regexp) *ExpectedActual {
	if p != nil {
		checker.expVarPattern = p
	}
	return checker
}

func (checker ExpectedActual) Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	switch call.Fn.Name {
	case "Equal", "Equalf", "NotEqual", "NotEqualf",
		"JSONEq", "JSONEqf", "YAMLEq", "YAMLEqf":
	default:
		return nil
	}

	if len(call.Args) < 2 {
		return nil
	}
	first, second := call.Args[0], call.Args[1]

	if checker.isWrongExpectedActualOrder(pass, first, second) {
		return newDiagnostic(checker.Name(), call, "need to reverse actual and expected values", &analysis.SuggestedFix{
			Message: "Reverse actual and expected values",
			TextEdits: []analysis.TextEdit{
				{
					Pos:     first.Pos(),
					End:     second.End(),
					NewText: formatAsCallArgs(pass, second, first),
				},
			},
		})
	}
	return nil
}

func (checker ExpectedActual) isWrongExpectedActualOrder(pass *analysis.Pass, first, second ast.Expr) bool {
	leftIsCandidate := checker.isExpectedValueCandidate(pass, first)
	rightIsCandidate := checker.isExpectedValueCandidate(pass, second)
	return rightIsCandidate && !leftIsCandidate
}

func (checker ExpectedActual) isExpectedValueCandidate(pass *analysis.Pass, expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.CompositeLit:
		return true

	case *ast.CallExpr:
		return isCastedBasicLitOrExpectedValue(v, checker.expVarPattern) ||
			isExpectedValueFactory(v, checker.expVarPattern)
	}

	return isBasicLit(expr) ||
		isUntypedConst(pass, expr) ||
		isTypedConst(pass, expr) ||
		isIdentNamedAsExpected(checker.expVarPattern, expr) ||
		isStructFieldNamedAsExpected(checker.expVarPattern, expr)
}

func isCastedBasicLitOrExpectedValue(ce *ast.CallExpr, pattern *regexp.Regexp) bool {
	if len(ce.Args) != 1 {
		return false
	}

	fn, ok := ce.Fun.(*ast.Ident)
	if !ok {
		return false
	}

	switch fn.Name {
	case "complex64", "complex128":
		return true

	case "uint", "uint8", "uint16", "uint32", "uint64",
		"int", "int8", "int16", "int32", "int64",
		"float32", "float64",
		"rune", "string":
		return isBasicLit(ce.Args[0]) || isIdentNamedAsExpected(pattern, ce.Args[0])
	}
	return false
}

func isExpectedValueFactory(ce *ast.CallExpr, pattern *regexp.Regexp) bool {
	if len(ce.Args) != 0 {
		return false
	}

	switch fn := ce.Fun.(type) {
	case *ast.Ident:
		return pattern.MatchString(fn.Name)
	case *ast.SelectorExpr:
		return pattern.MatchString(fn.Sel.Name)
	}
	return false
}

func isBasicLit(e ast.Expr) bool {
	_, ok := e.(*ast.BasicLit)
	return ok
}

func isUntypedConst(p *analysis.Pass, e ast.Expr) bool {
	t := p.TypesInfo.TypeOf(e)
	if t == nil {
		return false
	}

	b, ok := t.(*types.Basic)
	return ok && b.Info()&types.IsUntyped > 0
}

func isTypedConst(p *analysis.Pass, e ast.Expr) bool {
	tt, ok := p.TypesInfo.Types[e]
	return ok && tt.IsValue() && tt.Value != nil
}

func isIdentNamedAsExpected(pattern *regexp.Regexp, e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && pattern.MatchString(id.Name)
}

func isStructFieldNamedAsExpected(pattern *regexp.Regexp, e ast.Expr) bool {
	s, ok := e.(*ast.SelectorExpr)
	return ok && isIdentNamedAsExpected(pattern, s.Sel)
}
