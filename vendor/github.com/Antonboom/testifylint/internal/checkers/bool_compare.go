package checkers

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/Antonboom/testifylint/internal/analysisutil"
)

// BoolCompare detects situations like
//
//	assert.Equal(t, false, result)
//	assert.NotEqual(t, result, true)
//	assert.False(t, !result)
//	assert.True(t, result == true)
//	...
//
// and requires
//
//	assert.False(t, result)
//	assert.True(t, result)
type BoolCompare struct{} //

// NewBoolCompare constructs BoolCompare checker.
func NewBoolCompare() BoolCompare { return BoolCompare{} }
func (BoolCompare) Name() string  { return "bool-compare" }

func (checker BoolCompare) Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	newUseFnDiagnostic := func(proposed string, survivingArg ast.Node, replaceStart, replaceEnd token.Pos) *analysis.Diagnostic {
		return newUseFunctionDiagnostic(checker.Name(), call, proposed,
			newSuggestedFuncReplacement(call, proposed, analysis.TextEdit{
				Pos:     replaceStart,
				End:     replaceEnd,
				NewText: analysisutil.NodeBytes(pass.Fset, survivingArg),
			}),
		)
	}

	newUseTrueDiagnostic := func(survivingArg ast.Node, replaceStart, replaceEnd token.Pos) *analysis.Diagnostic {
		return newUseFnDiagnostic("True", survivingArg, replaceStart, replaceEnd)
	}

	newUseFalseDiagnostic := func(survivingArg ast.Node, replaceStart, replaceEnd token.Pos) *analysis.Diagnostic {
		return newUseFnDiagnostic("False", survivingArg, replaceStart, replaceEnd)
	}

	newNeedSimplifyDiagnostic := func(survivingArg ast.Node, replaceStart, replaceEnd token.Pos) *analysis.Diagnostic {
		return newDiagnostic(checker.Name(), call, "need to simplify the assertion",
			&analysis.SuggestedFix{
				Message: "Simplify the assertion",
				TextEdits: []analysis.TextEdit{{
					Pos:     replaceStart,
					End:     replaceEnd,
					NewText: analysisutil.NodeBytes(pass.Fset, survivingArg),
				}},
			},
		)
	}

	switch call.Fn.Name {
	case "Equal", "Equalf":
		if len(call.Args) < 2 {
			return nil
		}

		arg1, arg2 := call.Args[0], call.Args[1]
		t1, t2 := isUntypedTrue(pass, arg1), isUntypedTrue(pass, arg2)
		f1, f2 := isUntypedFalse(pass, arg1), isUntypedFalse(pass, arg2)

		switch {
		case xor(t1, t2):
			survivingArg, _ := anyVal([]bool{t1, t2}, arg2, arg1)
			return newUseTrueDiagnostic(survivingArg, arg1.Pos(), arg2.End())

		case xor(f1, f2):
			survivingArg, _ := anyVal([]bool{f1, f2}, arg2, arg1)
			return newUseFalseDiagnostic(survivingArg, arg1.Pos(), arg2.End())
		}

	case "NotEqual", "NotEqualf":
		if len(call.Args) < 2 {
			return nil
		}

		arg1, arg2 := call.Args[0], call.Args[1]
		t1, t2 := isUntypedTrue(pass, arg1), isUntypedTrue(pass, arg2)
		f1, f2 := isUntypedFalse(pass, arg1), isUntypedFalse(pass, arg2)

		switch {
		case xor(t1, t2):
			survivingArg, _ := anyVal([]bool{t1, t2}, arg2, arg1)
			return newUseFalseDiagnostic(survivingArg, arg1.Pos(), arg2.End())

		case xor(f1, f2):
			survivingArg, _ := anyVal([]bool{f1, f2}, arg2, arg1)
			return newUseTrueDiagnostic(survivingArg, arg1.Pos(), arg2.End())
		}

	case "True", "Truef":
		if len(call.Args) < 1 {
			return nil
		}
		expr := call.Args[0]

		{
			arg1, ok1 := isComparisonWithTrue(pass, expr, token.EQL)
			arg2, ok2 := isComparisonWithFalse(pass, expr, token.NEQ)

			if survivingArg, ok := anyVal([]bool{ok1, ok2}, arg1, arg2); ok {
				return newNeedSimplifyDiagnostic(survivingArg, expr.Pos(), expr.End())
			}
		}

		{
			arg1, ok1 := isComparisonWithTrue(pass, expr, token.NEQ)
			arg2, ok2 := isComparisonWithFalse(pass, expr, token.EQL)
			arg3, ok3 := isNegation(expr)

			if survivingArg, ok := anyVal([]bool{ok1, ok2, ok3}, arg1, arg2, arg3); ok {
				return newUseFalseDiagnostic(survivingArg, expr.Pos(), expr.End())
			}
		}

	case "False", "Falsef":
		if len(call.Args) < 1 {
			return nil
		}
		expr := call.Args[0]

		{
			arg1, ok1 := isComparisonWithTrue(pass, expr, token.EQL)
			arg2, ok2 := isComparisonWithFalse(pass, expr, token.NEQ)

			if survivingArg, ok := anyVal([]bool{ok1, ok2}, arg1, arg2); ok {
				return newNeedSimplifyDiagnostic(survivingArg, expr.Pos(), expr.End())
			}
		}

		{
			arg1, ok1 := isComparisonWithTrue(pass, expr, token.NEQ)
			arg2, ok2 := isComparisonWithFalse(pass, expr, token.EQL)
			arg3, ok3 := isNegation(expr)

			if survivingArg, ok := anyVal([]bool{ok1, ok2, ok3}, arg1, arg2, arg3); ok {
				return newUseTrueDiagnostic(survivingArg, expr.Pos(), expr.End())
			}
		}
	}
	return nil
}

var (
	falseObj = types.Universe.Lookup("false")
	trueObj  = types.Universe.Lookup("true")
)

func isUntypedTrue(pass *analysis.Pass, e ast.Expr) bool {
	return analysisutil.IsObj(pass.TypesInfo, e, trueObj)
}

func isUntypedFalse(pass *analysis.Pass, e ast.Expr) bool {
	return analysisutil.IsObj(pass.TypesInfo, e, falseObj)
}

func isComparisonWithTrue(pass *analysis.Pass, e ast.Expr, op token.Token) (ast.Expr, bool) {
	return isComparisonWith(pass, e, isUntypedTrue, op)
}

func isComparisonWithFalse(pass *analysis.Pass, e ast.Expr, op token.Token) (ast.Expr, bool) {
	return isComparisonWith(pass, e, isUntypedFalse, op)
}

type predicate func(pass *analysis.Pass, e ast.Expr) bool

func isComparisonWith(pass *analysis.Pass, e ast.Expr, predicate predicate, op token.Token) (ast.Expr, bool) {
	be, ok := e.(*ast.BinaryExpr)
	if !ok {
		return nil, false
	}
	if be.Op != op {
		return nil, false
	}

	t1, t2 := predicate(pass, be.X), predicate(pass, be.Y)
	if xor(t1, t2) {
		if t1 {
			return be.Y, true
		}
		return be.X, true
	}
	return nil, false
}

func isNegation(e ast.Expr) (ast.Expr, bool) {
	ue, ok := e.(*ast.UnaryExpr)
	if !ok {
		return nil, false
	}
	return ue.X, ue.Op == token.NOT
}

func xor(a, b bool) bool {
	return a != b
}

// anyVal returns the first value[i] for which bools[i] is true.
func anyVal[T any](bools []bool, vals ...T) (T, bool) {
	if len(bools) != len(vals) {
		panic("inconsistent usage of valOr") //nolint:forbidigo // Does not depend on the code being analyzed.
	}

	for i, b := range bools {
		if b {
			return vals[i], true
		}
	}

	var _default T
	return _default, false
}
