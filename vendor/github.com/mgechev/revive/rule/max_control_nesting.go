package rule

import (
	"fmt"
	"go/ast"
	"sync"

	"github.com/mgechev/revive/lint"
)

// MaxControlNestingRule lints given else constructs.
type MaxControlNestingRule struct {
	max int64

	configureOnce sync.Once
}

const defaultMaxControlNesting = 5

// Apply applies the rule to given file.
func (r *MaxControlNestingRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	r.configureOnce.Do(func() { r.configure(arguments) })

	var failures []lint.Failure

	fileAst := file.AST

	walker := &lintMaxControlNesting{
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
		max: int(r.max),
	}

	ast.Walk(walker, fileAst)

	return failures
}

// Name returns the rule name.
func (*MaxControlNestingRule) Name() string {
	return "max-control-nesting"
}

type lintMaxControlNesting struct {
	max             int
	onFailure       func(lint.Failure)
	nestingLevelAcc int
	lastCtrlStmt    ast.Node
}

func (w *lintMaxControlNesting) Visit(n ast.Node) ast.Visitor {
	if w.nestingLevelAcc > w.max { // we are visiting a node beyond the max nesting level
		w.onFailure(lint.Failure{
			Failure:    fmt.Sprintf("control flow nesting exceeds %d", w.max),
			Confidence: 1,
			Node:       w.lastCtrlStmt,
			Category:   "complexity",
		})
		return nil // stop visiting deeper
	}

	switch v := n.(type) {
	case *ast.IfStmt:
		w.lastCtrlStmt = v
		w.walkControlledBlock(v.Body) // "then" branch block
		if v.Else != nil {
			w.walkControlledBlock(v.Else) // "else" branch block
		}
		return nil // stop re-visiting nesting blocks (already visited by w.walkControlledBlock)

	case *ast.ForStmt:
		w.lastCtrlStmt = v
		w.walkControlledBlock(v.Body)
		return nil // stop re-visiting nesting blocks (already visited by w.walkControlledBlock)

	case *ast.CaseClause: // switch case
		w.lastCtrlStmt = v
		for _, s := range v.Body { // visit each statement in the case clause
			w.walkControlledBlock(s)
		}
		return nil // stop re-visiting nesting blocks (already visited by w.walkControlledBlock)

	case *ast.CommClause: // select case
		w.lastCtrlStmt = v
		for _, s := range v.Body { // visit each statement in the select case clause
			w.walkControlledBlock(s)
		}
		return nil // stop re-visiting nesting blocks (already visited by w.walkControlledBlock)

	case *ast.FuncLit:
		walker := &lintMaxControlNesting{
			onFailure: w.onFailure,
			max:       w.max,
		}
		ast.Walk(walker, v.Body)
		return nil
	}

	return w
}

func (w *lintMaxControlNesting) walkControlledBlock(b ast.Node) {
	oldNestingLevel := w.nestingLevelAcc
	w.nestingLevelAcc++
	ast.Walk(w, b)
	w.nestingLevelAcc = oldNestingLevel
}

func (r *MaxControlNestingRule) configure(arguments lint.Arguments) {
	if len(arguments) < 1 {
		r.max = defaultMaxControlNesting
		return
	}

	checkNumberOfArguments(1, arguments, r.Name())

	maxNesting, ok := arguments[0].(int64) // Alt. non panicking version
	if !ok {
		panic(`invalid value passed as argument number to the "max-control-nesting" rule`)
	}
	r.max = maxNesting
}
