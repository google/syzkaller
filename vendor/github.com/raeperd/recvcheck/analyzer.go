package recvcheck

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "recvcheck",
	Doc:      "checks for receiver type consistency",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

func run(pass *analysis.Pass) (any, error) {
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	structs := map[string]*structType{}
	inspector.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(n ast.Node) {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok || funcDecl.Recv == nil || len(funcDecl.Recv.List) != 1 {
			return
		}

		var recv *ast.Ident
		var isStar bool
		switch recvType := funcDecl.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			isStar = true
			if recv, ok = recvType.X.(*ast.Ident); !ok {
				return
			}
		case *ast.Ident:
			recv = recvType
		default:
			return
		}

		var st *structType
		st, ok = structs[recv.Name]
		if !ok {
			structs[recv.Name] = &structType{recv: recv.Name}
			st = structs[recv.Name]
		}

		if isStar {
			st.numStarMethod++
		} else {
			st.numTypeMethod++
		}
	})

	for _, st := range structs {
		if st.numStarMethod > 0 && st.numTypeMethod > 0 {
			pass.Reportf(pass.Pkg.Scope().Lookup(st.recv).Pos(), "the methods of %q use pointer receiver and non-pointer receiver.", st.recv)
		}
	}

	return nil, nil
}

type structType struct {
	recv          string
	numStarMethod int
	numTypeMethod int
}
