package checkers

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/Antonboom/testifylint/internal/analysisutil"
)

// ErrorNil detects situations like
//
//	assert.Nil(t, err)
//	assert.NotNil(t, err)
//	assert.Equal(t, nil, err)
//	assert.EqualValues(t, nil, err)
//	assert.Exactly(t, nil, err)
//	assert.ErrorIs(t, err, nil)
//
//	assert.NotEqual(t, nil, err)
//	assert.NotEqualValues(t, nil, err)
//	assert.NotErrorIs(t, err, nil)
//
// and requires
//
//	assert.NoError(t, err)
//	assert.Error(t, err)
type ErrorNil struct{}

// NewErrorNil constructs ErrorNil checker.
func NewErrorNil() ErrorNil   { return ErrorNil{} }
func (ErrorNil) Name() string { return "error-nil" }

func (checker ErrorNil) Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	const (
		errorFn   = "Error"
		noErrorFn = "NoError"
	)

	proposedFn, survivingArg, replacementEndPos := func() (string, ast.Expr, token.Pos) {
		switch call.Fn.NameFTrimmed {
		case "Nil":
			if len(call.Args) >= 1 && isError(pass, call.Args[0]) {
				return noErrorFn, call.Args[0], call.Args[0].End()
			}

		case "NotNil":
			if len(call.Args) >= 1 && isError(pass, call.Args[0]) {
				return errorFn, call.Args[0], call.Args[0].End()
			}

		case "Equal", "EqualValues", "Exactly", "ErrorIs":
			if len(call.Args) < 2 {
				return "", nil, token.NoPos
			}
			a, b := call.Args[0], call.Args[1]

			switch {
			case isError(pass, a) && isNil(b):
				return noErrorFn, a, b.End()
			case isNil(a) && isError(pass, b):
				return noErrorFn, b, b.End()
			}

		case "NotEqual", "NotEqualValues", "NotErrorIs":
			if len(call.Args) < 2 {
				return "", nil, token.NoPos
			}
			a, b := call.Args[0], call.Args[1]

			switch {
			case isError(pass, a) && isNil(b):
				return errorFn, a, b.End()
			case isNil(a) && isError(pass, b):
				return errorFn, b, b.End()
			}
		}
		return "", nil, token.NoPos
	}()

	if proposedFn != "" {
		return newUseFunctionDiagnostic(checker.Name(), call, proposedFn,
			newSuggestedFuncReplacement(call, proposedFn, analysis.TextEdit{
				Pos:     call.Args[0].Pos(),
				End:     replacementEndPos,
				NewText: analysisutil.NodeBytes(pass.Fset, survivingArg),
			}),
		)
	}
	return nil
}

var (
	errorType  = types.Universe.Lookup("error").Type()
	errorIface = errorType.Underlying().(*types.Interface)
)

func isError(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}

	_, ok := t.Underlying().(*types.Interface)
	return ok && types.Implements(t, errorIface)
}

func isNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}
