package analyzer

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name:     "perfsprint",
	Doc:      "Checks that fmt.Sprintf can be replaced with a faster alternative.",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

func run(pass *analysis.Pass) (interface{}, error) {
	var fmtSprintObj, fmtSprintfObj types.Object
	for _, pkg := range pass.Pkg.Imports() {
		if pkg.Path() == "fmt" {
			fmtSprintObj = pkg.Scope().Lookup("Sprint")
			fmtSprintfObj = pkg.Scope().Lookup("Sprintf")
		}
	}
	if fmtSprintfObj == nil {
		return nil, nil
	}

	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}
	insp.Preorder(nodeFilter, func(node ast.Node) {
		call := node.(*ast.CallExpr)
		called, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		calledObj := pass.TypesInfo.ObjectOf(called.Sel)

		var (
			fn    string
			verb  string
			value ast.Expr
			err   error
		)
		switch {
		case calledObj == fmtSprintObj && len(call.Args) == 1:
			fn = "fmt.Sprint"
			verb = "%v"
			value = call.Args[0]

		case calledObj == fmtSprintfObj && len(call.Args) == 2:
			verbLit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return
			}
			verb, err = strconv.Unquote(verbLit.Value)
			if err != nil {
				// Probably unreachable.
				return
			}

			fn = "fmt.Sprintf"
			value = call.Args[1]

		default:
			return
		}

		switch verb {
		default:
			return
		case "%d", "%v", "%x", "%t", "%s":
		}

		valueType := pass.TypesInfo.TypeOf(value)
		a, isArray := valueType.(*types.Array)
		s, isSlice := valueType.(*types.Slice)

		var d *analysis.Diagnostic
		switch {
		case isBasicType(valueType, types.String) && oneOf(verb, "%v", "%s"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with just using the string",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Just use string value",
						TextEdits: []analysis.TextEdit{{
							Pos:     call.Pos(),
							End:     call.End(),
							NewText: []byte(formatNode(pass.Fset, value)),
						}},
					},
				},
			}

		case types.Implements(valueType, errIface) && oneOf(verb, "%v", "%s"):
			errMethodCall := formatNode(pass.Fset, value) + ".Error()"
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with " + errMethodCall,
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use " + errMethodCall,
						TextEdits: []analysis.TextEdit{{
							Pos:     call.Pos(),
							End:     call.End(),
							NewText: []byte(errMethodCall),
						}},
					},
				},
			}

		case isBasicType(valueType, types.Bool) && oneOf(verb, "%v", "%t"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.FormatBool",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.FormatBool",
						TextEdits: []analysis.TextEdit{{
							Pos:     call.Pos(),
							End:     value.Pos(),
							NewText: []byte("strconv.FormatBool("),
						}},
					},
				},
			}

		case isArray && isBasicType(a.Elem(), types.Uint8) && oneOf(verb, "%x"):
			if _, ok := value.(*ast.Ident); !ok {
				// Doesn't support array literals.
				return
			}

			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster hex.EncodeToString",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use hex.EncodeToString",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     call.Pos(),
								End:     value.Pos(),
								NewText: []byte("hex.EncodeToString("),
							},
							{
								Pos:     value.End(),
								End:     value.End(),
								NewText: []byte("[:]"),
							},
						},
					},
				},
			}
		case isSlice && isBasicType(s.Elem(), types.Uint8) && oneOf(verb, "%x"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster hex.EncodeToString",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use hex.EncodeToString",
						TextEdits: []analysis.TextEdit{{
							Pos:     call.Pos(),
							End:     value.Pos(),
							NewText: []byte("hex.EncodeToString("),
						}},
					},
				},
			}

		case isBasicType(valueType, types.Int8, types.Int16, types.Int32) && oneOf(verb, "%v", "%d"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.Itoa",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.Itoa",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     call.Pos(),
								End:     value.Pos(),
								NewText: []byte("strconv.Itoa(int("),
							},
							{
								Pos:     value.End(),
								End:     value.End(),
								NewText: []byte(")"),
							},
						},
					},
				},
			}
		case isBasicType(valueType, types.Int) && oneOf(verb, "%v", "%d"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.Itoa",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.Itoa",
						TextEdits: []analysis.TextEdit{{
							Pos:     call.Pos(),
							End:     value.Pos(),
							NewText: []byte("strconv.Itoa("),
						}},
					},
				},
			}
		case isBasicType(valueType, types.Int64) && oneOf(verb, "%v", "%d"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.FormatInt",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.FormatInt",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     call.Pos(),
								End:     value.Pos(),
								NewText: []byte("strconv.FormatInt("),
							},
							{
								Pos:     value.End(),
								End:     value.End(),
								NewText: []byte(", 10"),
							},
						},
					},
				},
			}

		case isBasicType(valueType, types.Uint8, types.Uint16, types.Uint32, types.Uint) && oneOf(verb, "%v", "%d"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.FormatUint",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.FormatUint",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     call.Pos(),
								End:     value.Pos(),
								NewText: []byte("strconv.FormatUint(uint64("),
							},
							{
								Pos:     value.End(),
								End:     value.End(),
								NewText: []byte("), 10"),
							},
						},
					},
				},
			}
		case isBasicType(valueType, types.Uint64) && oneOf(verb, "%v", "%d"):
			d = &analysis.Diagnostic{
				Pos:     call.Pos(),
				End:     call.End(),
				Message: fn + " can be replaced with faster strconv.FormatUint",
				SuggestedFixes: []analysis.SuggestedFix{
					{
						Message: "Use strconv.FormatUint",
						TextEdits: []analysis.TextEdit{
							{
								Pos:     call.Pos(),
								End:     value.Pos(),
								NewText: []byte("strconv.FormatUint("),
							},
							{
								Pos:     value.End(),
								End:     value.End(),
								NewText: []byte(", 10"),
							},
						},
					},
				},
			}
		}

		if d != nil {
			// Need to run goimports to fix using of fmt, strconv or encoding/hex afterwards.
			pass.Report(*d)
		}
	})

	return nil, nil
}

var errIface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func isBasicType(lhs types.Type, expected ...types.BasicKind) bool {
	for _, rhs := range expected {
		if types.Identical(lhs, types.Typ[rhs]) {
			return true
		}
	}
	return false
}

func formatNode(fset *token.FileSet, node ast.Node) string {
	buf := new(bytes.Buffer)
	if err := format.Node(buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}

func oneOf[T comparable](v T, expected ...T) bool {
	for _, rhs := range expected {
		if v == rhs {
			return true
		}
	}
	return false
}
