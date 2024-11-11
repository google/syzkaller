package checkers

import (
	"go/ast"
	"go/token"
	"regexp"

	"golang.org/x/tools/go/analysis"

	"github.com/Antonboom/testifylint/internal/analysisutil"
)

var (
	jsonIdentRe = regexp.MustCompile(`json|JSON|Json`)
	yamlIdentRe = regexp.MustCompile(`yaml|YAML|Yaml|yml|YML|Yml`)
)

func isJSONStyleExpr(pass *analysis.Pass, e ast.Expr) bool {
	if isIdentNamedAfterPattern(jsonIdentRe, e) {
		return true
	}

	if t, ok := pass.TypesInfo.Types[e]; ok && t.Value != nil {
		return analysisutil.IsJSONLike(t.Value.String())
	}

	if bl, ok := e.(*ast.BasicLit); ok {
		return bl.Kind == token.STRING && analysisutil.IsJSONLike(bl.Value)
	}

	if args, ok := isFmtSprintfCall(pass, e); ok {
		return isJSONStyleExpr(pass, args[0])
	}

	return false
}

func isYAMLStyleExpr(e ast.Expr) bool {
	return isIdentNamedAfterPattern(yamlIdentRe, e)
}
