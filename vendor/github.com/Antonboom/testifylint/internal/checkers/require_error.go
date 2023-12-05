package checkers

import "golang.org/x/tools/go/analysis"

// RequireError detects situations like
//
//	assert.NoError(t, err)
//	s.ErrorIs(err, io.EOF)
//	s.Assert().Error(err)
//
// and requires
//
//	require.NoError(t, err)
//	s.Require().ErrorIs(err, io.EOF)
//	s.Require().Error(err)
type RequireError struct{}

// NewRequireError constructs RequireError checker.
func NewRequireError() RequireError { return RequireError{} }
func (RequireError) Name() string   { return "require-error" }

func (checker RequireError) Check(_ *analysis.Pass, call *CallMeta) *analysis.Diagnostic {
	if !call.IsAssert {
		return nil
	}

	const msg = "for error assertions use require"

	switch call.Fn.Name {
	case "Error", "ErrorIs", "ErrorAs", "EqualError", "ErrorContains", "NoError", "NotErrorIs",
		"Errorf", "ErrorIsf", "ErrorAsf", "EqualErrorf", "ErrorContainsf", "NoErrorf", "NotErrorIsf":
		return newDiagnostic(checker.Name(), call, msg, nil)
	}
	return nil
}
