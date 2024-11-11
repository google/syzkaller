package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// GetReturnRule lints given else constructs.
type GetReturnRule struct{}

// Apply applies the rule to given file.
func (*GetReturnRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	onFailure := func(failure lint.Failure) {
		failures = append(failures, failure)
	}

	w := lintReturnRule{onFailure}
	ast.Walk(w, file.AST)
	return failures
}

// Name returns the rule name.
func (*GetReturnRule) Name() string {
	return "get-return"
}

type lintReturnRule struct {
	onFailure func(lint.Failure)
}

const getterPrefix = "GET"

var lenGetterPrefix = len(getterPrefix)

func isGetter(name string) bool {
	nameHasGetterPrefix := strings.HasPrefix(strings.ToUpper(name), getterPrefix)
	if !nameHasGetterPrefix {
		return false
	}

	isJustGet := len(name) == lenGetterPrefix
	if isJustGet {
		return false
	}

	c := name[lenGetterPrefix]
	lowerCaseAfterGetterPrefix := c >= 'a' && c <= 'z'

	return !lowerCaseAfterGetterPrefix
}

func hasResults(rs *ast.FieldList) bool {
	return rs != nil && len(rs.List) > 0
}

func (w lintReturnRule) Visit(node ast.Node) ast.Visitor {
	fd, ok := node.(*ast.FuncDecl)
	if !ok {
		return w
	}

	if !isGetter(fd.Name.Name) {
		return w
	}
	if !hasResults(fd.Type.Results) {
		w.onFailure(lint.Failure{
			Confidence: 0.8,
			Node:       fd,
			Category:   "logic",
			Failure:    fmt.Sprintf("function '%s' seems to be a getter but it does not return any result", fd.Name.Name),
		})
	}

	return w
}
