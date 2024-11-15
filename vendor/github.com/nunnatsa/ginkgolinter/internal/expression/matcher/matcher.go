package matcher

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"

	"github.com/nunnatsa/ginkgolinter/internal/gomegahandler"
)

const ( // gomega matchers
	beEmpty        = "BeEmpty"
	beEquivalentTo = "BeEquivalentTo"
	beFalse        = "BeFalse"
	beIdenticalTo  = "BeIdenticalTo"
	beNil          = "BeNil"
	beNumerically  = "BeNumerically"
	beTrue         = "BeTrue"
	beZero         = "BeZero"
	equal          = "Equal"
	haveLen        = "HaveLen"
	haveValue      = "HaveValue"
	and            = "And"
	or             = "Or"
	withTransform  = "WithTransform"
	matchError     = "MatchError"
	haveOccurred   = "HaveOccurred"
	succeed        = "Succeed"
)

type Matcher struct {
	funcName     string
	Orig         *ast.CallExpr
	Clone        *ast.CallExpr
	info         Info
	reverseLogic bool
	handler      gomegahandler.Handler
}

func New(origMatcher, matcherClone *ast.CallExpr, pass *analysis.Pass, handler gomegahandler.Handler) (*Matcher, bool) {
	reverse := false
	var assertFuncName string
	for {
		ok := false
		assertFuncName, ok = handler.GetActualFuncName(origMatcher)
		if !ok {
			return nil, false
		}

		if assertFuncName != "Not" {
			break
		}

		reverse = !reverse
		origMatcher, ok = origMatcher.Args[0].(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		matcherClone = matcherClone.Args[0].(*ast.CallExpr)
	}

	return &Matcher{
		funcName:     assertFuncName,
		Orig:         origMatcher,
		Clone:        matcherClone,
		info:         getMatcherInfo(origMatcher, matcherClone, assertFuncName, pass, handler),
		reverseLogic: reverse,
		handler:      handler,
	}, true
}

func (m *Matcher) ShouldReverseLogic() bool {
	return m.reverseLogic
}

func (m *Matcher) GetMatcherInfo() Info {
	return m.info
}

func (m *Matcher) ReplaceMatcherFuncName(name string) {
	m.handler.ReplaceFunction(m.Clone, ast.NewIdent(name))
}

func (m *Matcher) ReplaceMatcherArgs(newArgs []ast.Expr) {
	m.Clone.Args = newArgs
}
