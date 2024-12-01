package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/mgechev/revive/lint"
)

// ModifiesValRecRule lints assignments to value method-receivers.
type ModifiesValRecRule struct{}

// Apply applies the rule to given file.
func (*ModifiesValRecRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	onFailure := func(failure lint.Failure) {
		failures = append(failures, failure)
	}

	w := lintModifiesValRecRule{file: file, onFailure: onFailure}
	file.Pkg.TypeCheck()
	ast.Walk(w, file.AST)

	return failures
}

// Name returns the rule name.
func (*ModifiesValRecRule) Name() string {
	return "modifies-value-receiver"
}

type lintModifiesValRecRule struct {
	file      *lint.File
	onFailure func(lint.Failure)
}

func (w lintModifiesValRecRule) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	case *ast.FuncDecl:
		if n.Recv == nil {
			return nil // skip, not a method
		}

		receiver := n.Recv.List[0]
		if _, ok := receiver.Type.(*ast.StarExpr); ok {
			return nil // skip, method with pointer receiver
		}

		if w.skipType(receiver.Type) {
			return nil // skip, receiver is a map or array
		}

		if len(receiver.Names) < 1 {
			return nil // skip, anonymous receiver
		}

		receiverName := receiver.Names[0].Name
		if receiverName == "_" {
			return nil // skip, anonymous receiver
		}

		receiverAssignmentFinder := func(n ast.Node) bool {
			// look for assignments with the receiver in the right hand
			assignment, ok := n.(*ast.AssignStmt)
			if !ok {
				return false
			}

			for _, exp := range assignment.Lhs {
				switch e := exp.(type) {
				case *ast.IndexExpr: // receiver...[] = ...
					continue
				case *ast.StarExpr: // *receiver = ...
					continue
				case *ast.SelectorExpr: // receiver.field = ...
					name := w.getNameFromExpr(e.X)
					if name == "" || name != receiverName {
						continue
					}
				case *ast.Ident: // receiver := ...
					if e.Name != receiverName {
						continue
					}
				default:
					continue
				}

				return true
			}

			return false
		}

		assignmentsToReceiver := pick(n.Body, receiverAssignmentFinder)
		if len(assignmentsToReceiver) == 0 {
			return nil // receiver is not modified
		}

		methodReturnsReceiver := len(w.findReturnReceiverStatements(receiverName, n.Body)) > 0
		if methodReturnsReceiver {
			return nil // modification seems legit (see issue #1066)
		}

		for _, assignment := range assignmentsToReceiver {
			w.onFailure(lint.Failure{
				Node:       assignment,
				Confidence: 1,
				Failure:    "suspicious assignment to a by-value method receiver",
			})
		}
	}

	return w
}

func (w lintModifiesValRecRule) skipType(t ast.Expr) bool {
	rt := w.file.Pkg.TypeOf(t)
	if rt == nil {
		return false
	}

	rt = rt.Underlying()
	rtName := rt.String()

	// skip when receiver is a map or array
	return strings.HasPrefix(rtName, "[]") || strings.HasPrefix(rtName, "map[")
}

func (lintModifiesValRecRule) getNameFromExpr(ie ast.Expr) string {
	ident, ok := ie.(*ast.Ident)
	if !ok {
		return ""
	}

	return ident.Name
}

func (w lintModifiesValRecRule) findReturnReceiverStatements(receiverName string, target ast.Node) []ast.Node {
	finder := func(n ast.Node) bool {
		// look for returns with the receiver as value
		returnStatement, ok := n.(*ast.ReturnStmt)
		if !ok {
			return false
		}

		for _, exp := range returnStatement.Results {
			switch e := exp.(type) {
			case *ast.SelectorExpr: // receiver.field = ...
				name := w.getNameFromExpr(e.X)
				if name == "" || name != receiverName {
					continue
				}
			case *ast.Ident: // receiver := ...
				if e.Name != receiverName {
					continue
				}
			case *ast.UnaryExpr:
				if e.Op != token.AND {
					continue
				}
				name := w.getNameFromExpr(e.X)
				if name == "" || name != receiverName {
					continue
				}

			default:
				continue
			}

			return true
		}

		return false
	}

	return pick(target, finder)
}
