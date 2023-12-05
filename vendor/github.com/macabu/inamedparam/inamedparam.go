package inamedparam

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name: "inamedparam",
	Doc:  "reports interfaces with unnamed method parameters",
	Run:  run,
	Requires: []*analysis.Analyzer{
		inspect.Analyzer,
	},
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	types := []ast.Node{
		&ast.InterfaceType{},
	}

	inspect.Preorder(types, func(n ast.Node) {
		interfaceType, ok := n.(*ast.InterfaceType)
		if !ok || interfaceType == nil || interfaceType.Methods == nil {
			return
		}

		for _, method := range interfaceType.Methods.List {
			interfaceFunc, ok := method.Type.(*ast.FuncType)
			if !ok || interfaceFunc == nil || interfaceFunc.Params == nil {
				continue
			}

			methodName := method.Names[0].Name

			for _, param := range interfaceFunc.Params.List {
				if param.Names == nil {
					var builtParamType string

					switch paramType := param.Type.(type) {
					case *ast.SelectorExpr:
						if ident := paramType.X.(*ast.Ident); ident != nil {
							builtParamType += ident.Name + "."
						}

						builtParamType += paramType.Sel.Name
					case *ast.Ident:
						builtParamType = paramType.Name
					}

					if builtParamType != "" {
						pass.Reportf(param.Pos(), "interface method %v must have named param for type %v", methodName, builtParamType)
					} else {
						pass.Reportf(param.Pos(), "interface method %v must have all named params", methodName)
					}
				}
			}
		}
	})

	return nil, nil
}
