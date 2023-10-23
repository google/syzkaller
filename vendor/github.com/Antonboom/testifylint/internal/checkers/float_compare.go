package checkers

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// FloatCompare detects situation like
//
//	assert.Equal(t, 42.42, a)
//	assert.True(t, a == 42.42)
//	assert.False(t, a != 42.42)
//
// and requires
//
//	assert.InEpsilon(t, 42.42, a, 0.0001) // Or assert.InDelta
type FloatCompare struct{}

// NewFloatCompare constructs FloatCompare checker.
func NewFloatCompare() FloatCompare { return FloatCompare{} }
func (FloatCompare) Name() string   { return "float-compare" }

func (checker FloatCompare) Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	invalid := func() bool {
		switch call.Fn.Name {
		case "Equal", "Equalf":
			return len(call.Args) > 1 && isFloat(pass, call.Args[0]) && isFloat(pass, call.Args[1])

		case "True", "Truef":
			return len(call.Args) > 0 && isFloatCompare(pass, call.Args[0], token.EQL)

		case "False", "Falsef":
			return len(call.Args) > 0 && isFloatCompare(pass, call.Args[0], token.NEQ)
		}
		return false
	}()

	if invalid {
		return newUseFunctionDiagnostic(checker.Name(), call, "InEpsilon (or InDelta)", nil)
	}
	return nil
}

func isFloat(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}

	bt, ok := t.Underlying().(*types.Basic)
	return ok && (bt.Info()&types.IsFloat > 0)
}

func isFloatCompare(p *analysis.Pass, e ast.Expr, op token.Token) bool {
	be, ok := e.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	return be.Op == op && (isFloat(p, be.X) || isFloat(p, be.Y))
}
