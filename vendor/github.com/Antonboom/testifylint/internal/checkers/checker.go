package checkers

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/inspector"
)

// CallMeta stores meta info about assertion function/method call, for example
//
//	assert.Equal(t, 42, result, "helpful comment")
type CallMeta struct {
	// Range contains start and end position of assertion call.
	analysis.Range
	// IsPkg true if this is package (not object) call.
	IsPkg bool
	// IsAssert true if this is "testify/assert" package (or object) call.
	IsAssert bool
	// Selector is the AST expression of "assert.Equal".
	Selector *ast.SelectorExpr
	// SelectorXStr is a string representation of Selector's left part – value before point, e.g. "assert".
	SelectorXStr string
	// Fn stores meta info about assertion function itself.
	Fn FnMeta
	// Args stores assertion call arguments but without `t *testing.T` argument.
	// E.g [42, result, "helpful comment"].
	Args []ast.Expr
	// ArgsRaw stores assertion call initial arguments.
	// E.g [t, 42, result, "helpful comment"].
	ArgsRaw []ast.Expr
}

// FnMeta stores meta info about assertion function itself, for example "Equal".
type FnMeta struct {
	// Range contains start and end position of function Name.
	analysis.Range
	// Name is a function name.
	Name string
	// IsFmt is true if function is formatted, e.g. "Equalf".
	IsFmt bool
}

// Checker describes named checker.
type Checker interface {
	Name() string
}

// RegularChecker check assertion call presented in CallMeta form.
type RegularChecker interface {
	Checker
	Check(pass *analysis.Pass, call *CallMeta) *analysis.Diagnostic
}

// AdvancedChecker implements complex Check logic different from trivial CallMeta check.
type AdvancedChecker interface {
	Checker
	Check(pass *analysis.Pass, inspector *inspector.Inspector) []analysis.Diagnostic
}
