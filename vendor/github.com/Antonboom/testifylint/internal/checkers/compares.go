package checkers

import (
	"bytes"
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"

	"github.com/Antonboom/testifylint/internal/analysisutil"
)

// Compares detects situations like
//
//	assert.True(t, a == b)
//	assert.True(t, a != b)
//	assert.True(t, a > b)
//	assert.True(t, a >= b)
//	assert.True(t, a < b)
//	assert.True(t, a <= b)
//	assert.False(t, a == b)
//	...
//
// and requires
//
//	assert.Equal(t, a, b)
//	assert.NotEqual(t, a, b)
//	assert.Greater(t, a, b)
//	assert.GreaterOrEqual(t, a, b)
//	assert.Less(t, a, b)
//	assert.LessOrEqual(t, a, b)
type Compares struct{}

// NewCompares constructs Compares checker.
func NewCompares() Compares   { return Compares{} }
func (Compares) Name() string { return "compares" }

func (checker Compares) Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	if len(call.Args) < 1 {
		return nil
	}

	be, ok := call.Args[0].(*ast.BinaryExpr)
	if !ok {
		return nil
	}

	var tokenToProposedFn map[token.Token]string

	switch call.Fn.NameFTrimmed {
	case "True":
		tokenToProposedFn = tokenToProposedFnInsteadOfTrue
	case "False":
		tokenToProposedFn = tokenToProposedFnInsteadOfFalse
	default:
		return nil
	}

	if proposedFn, ok := tokenToProposedFn[be.Op]; ok {
		a, b := be.X, be.Y
		return newUseFunctionDiagnostic(checker.Name(), call, proposedFn,
			newSuggestedFuncReplacement(call, proposedFn, analysis.TextEdit{
				Pos:     be.X.Pos(),
				End:     be.Y.End(),
				NewText: formatAsCallArgs(pass, a, b),
			}),
		)
	}
	return nil
}

var tokenToProposedFnInsteadOfTrue = map[token.Token]string{
	token.EQL: "Equal",
	token.NEQ: "NotEqual",
	token.GTR: "Greater",
	token.GEQ: "GreaterOrEqual",
	token.LSS: "Less",
	token.LEQ: "LessOrEqual",
}

var tokenToProposedFnInsteadOfFalse = map[token.Token]string{
	token.EQL: "NotEqual",
	token.NEQ: "Equal",
	token.GTR: "LessOrEqual",
	token.GEQ: "Less",
	token.LSS: "GreaterOrEqual",
	token.LEQ: "Greater",
}

// formatAsCallArgs joins a and b and return bytes like `a, b`.
func formatAsCallArgs(pass *analysis.Pass, a, b ast.Node) []byte {
	return bytes.Join([][]byte{
		analysisutil.NodeBytes(pass.Fset, a),
		analysisutil.NodeBytes(pass.Fset, b),
	}, []byte(", "))
}
