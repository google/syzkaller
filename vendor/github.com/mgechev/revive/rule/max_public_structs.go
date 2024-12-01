package rule

import (
	"fmt"
	"go/ast"
	"strings"
	"sync"

	"github.com/mgechev/revive/lint"
)

// MaxPublicStructsRule lints given else constructs.
type MaxPublicStructsRule struct {
	max int64

	configureOnce sync.Once
}

const defaultMaxPublicStructs = 5

func (r *MaxPublicStructsRule) configure(arguments lint.Arguments) {
	if len(arguments) < 1 {
		r.max = defaultMaxPublicStructs
		return
	}

	checkNumberOfArguments(1, arguments, r.Name())

	maxStructs, ok := arguments[0].(int64) // Alt. non panicking version
	if !ok {
		panic(`invalid value passed as argument number to the "max-public-structs" rule`)
	}
	r.max = maxStructs
}

// Apply applies the rule to given file.
func (r *MaxPublicStructsRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	r.configureOnce.Do(func() { r.configure(arguments) })

	var failures []lint.Failure

	if r.max < 1 {
		return failures
	}

	fileAst := file.AST

	walker := &lintMaxPublicStructs{
		fileAst: fileAst,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	ast.Walk(walker, fileAst)

	if walker.current > r.max {
		walker.onFailure(lint.Failure{
			Failure:    fmt.Sprintf("you have exceeded the maximum number (%d) of public struct declarations", r.max),
			Confidence: 1,
			Node:       fileAst,
			Category:   "style",
		})
	}

	return failures
}

// Name returns the rule name.
func (*MaxPublicStructsRule) Name() string {
	return "max-public-structs"
}

type lintMaxPublicStructs struct {
	current   int64
	fileAst   *ast.File
	onFailure func(lint.Failure)
}

func (w *lintMaxPublicStructs) Visit(n ast.Node) ast.Visitor {
	switch v := n.(type) {
	case *ast.TypeSpec:
		name := v.Name.Name
		first := string(name[0])
		if strings.ToUpper(first) == first {
			w.current++
		}
	}
	return w
}
