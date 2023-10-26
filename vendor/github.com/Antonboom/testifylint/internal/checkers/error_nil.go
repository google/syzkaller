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
//	assert.Equal(t, err, nil)
//	assert.NotEqual(t, err, nil)
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
		switch call.Fn.Name {
		case "NotNil", "NotNilf":
			if len(call.Args) >= 1 && isError(pass, call.Args[0]) {
				return errorFn, call.Args[0], call.Args[0].End()
			}

		case "Nil", "Nilf":
			if len(call.Args) >= 1 && isError(pass, call.Args[0]) {
				return noErrorFn, call.Args[0], call.Args[0].End()
			}

		case "Equal", "Equalf":
			if len(call.Args) < 2 {
				return "", nil, token.NoPos
			}
			a, b := call.Args[0], call.Args[1]

			switch {
			case isError(pass, a) && isNil(pass, b):
				return noErrorFn, a, b.End()
			case isNil(pass, a) && isError(pass, b):
				return noErrorFn, b, b.End()
			}

		case "NotEqual", "NotEqualf":
			if len(call.Args) < 2 {
				return "", nil, token.NoPos
			}
			a, b := call.Args[0], call.Args[1]

			switch {
			case isError(pass, a) && isNil(pass, b):
				return errorFn, a, b.End()
			case isNil(pass, a) && isError(pass, b):
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

var errIface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func isError(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}

	_, ok := t.Underlying().(*types.Interface)
	return ok && types.Implements(t, errIface)
}

func isNil(pass *analysis.Pass, expr ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(expr)
	if t == nil {
		return false
	}

	b, ok := t.(*types.Basic)
	return ok && b.Kind()&types.UntypedNil > 0
}
