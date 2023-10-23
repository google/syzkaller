package checkers

import (
	"fmt"
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/Antonboom/testifylint/internal/analysisutil"
	"github.com/Antonboom/testifylint/internal/testify"
)

// SuiteTHelper requires t.Helper() call in suite helpers:
//
//	func (s *RoomSuite) assertRoomRound(roundID RoundID) {
//		s.T().Helper()
//		s.Equal(roundID, s.getRoom().CurrentRound.ID)
//	}
type SuiteTHelper struct{}

// NewSuiteTHelper constructs SuiteTHelper checker.
func NewSuiteTHelper() SuiteTHelper { return SuiteTHelper{} }
func (SuiteTHelper) Name() string   { return "suite-thelper" }

func (checker SuiteTHelper) Check(pass *analysis.Pass, inspector *inspector.Inspector) (diagnostics []analysis.Diagnostic) {
	inspector.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(node ast.Node) {
		fd := node.(*ast.FuncDecl)
		if !isTestifySuiteMethod(pass, fd) {
			return
		}

		if ident := fd.Name; ident == nil || isTestMethod(ident.Name) || isServiceMethod(ident.Name) {
			return
		}

		if !containsSuiteAssertions(pass, fd) {
			return
		}

		rcv := fd.Recv.List[0]
		if len(rcv.Names) != 1 || rcv.Names[0] == nil {
			return
		}
		rcvName := rcv.Names[0].Name

		helperCallStr := fmt.Sprintf("%s.T().Helper()", rcvName)

		firstStmt := fd.Body.List[0]
		if analysisutil.NodeString(pass.Fset, firstStmt) == helperCallStr {
			return
		}

		msg := fmt.Sprintf("suite helper method must start with " + helperCallStr)
		d := newDiagnostic(checker.Name(), fd, msg, &analysis.SuggestedFix{
			Message: fmt.Sprintf("Insert `%s`", helperCallStr),
			TextEdits: []analysis.TextEdit{
				{
					Pos:     firstStmt.Pos(),
					End:     firstStmt.Pos(), // Pure insertion.
					NewText: []byte(helperCallStr + "\n\n"),
				},
			},
		})
		diagnostics = append(diagnostics, *d)
	})
	return diagnostics
}

func isTestifySuiteMethod(pass *analysis.Pass, fDecl *ast.FuncDecl) bool {
	if fDecl.Recv == nil || len(fDecl.Recv.List) != 1 {
		return false
	}

	rcv := fDecl.Recv.List[0]
	return implementsTestifySuiteIface(pass, rcv.Type)
}

func isTestMethod(name string) bool {
	return strings.HasPrefix(name, "Test")
}

func isServiceMethod(name string) bool {
	// https://github.com/stretchr/testify/blob/master/suite/interfaces.go
	switch name {
	case "T", "SetT", "SetS", "SetupSuite", "SetupTest", "TearDownSuite", "TearDownTest",
		"BeforeTest", "AfterTest", "HandleStats", "SetupSubTest", "TearDownSubTest":
		return true
	}
	return false
}

func containsSuiteAssertions(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}

	for _, s := range fn.Body.List {
		if isSuiteAssertion(pass, s) {
			return true
		}
	}
	return false
}

func isSuiteAssertion(pass *analysis.Pass, stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}

	ce, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}

	se, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok || se.Sel == nil {
		return false
	}

	if sel, ok := pass.TypesInfo.Selections[se]; ok {
		pkg := sel.Obj().Pkg()
		isAssert := analysisutil.IsPkg(pkg, testify.AssertPkgName, testify.AssertPkgPath)
		isRequire := analysisutil.IsPkg(pkg, testify.RequirePkgName, testify.RequirePkgPath)
		return isAssert || isRequire
	}
	return false
}
