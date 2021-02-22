package ruleguard

import (
	"go/ast"
)

type nodeCategory int

const (
	nodeUnknown nodeCategory = iota

	nodeArrayType
	nodeAssignStmt
	nodeBasicLit
	nodeBinaryExpr
	nodeBlockStmt
	nodeBranchStmt
	nodeCallExpr
	nodeCaseClause
	nodeChanType
	nodeCommClause
	nodeCompositeLit
	nodeDeclStmt
	nodeDeferStmt
	nodeEllipsis
	nodeEmptyStmt
	nodeExprStmt
	nodeForStmt
	nodeFuncDecl
	nodeFuncLit
	nodeFuncType
	nodeGenDecl
	nodeGoStmt
	nodeIdent
	nodeIfStmt
	nodeImportSpec
	nodeIncDecStmt
	nodeIndexExpr
	nodeInterfaceType
	nodeKeyValueExpr
	nodeLabeledStmt
	nodeMapType
	nodeParenExpr
	nodeRangeStmt
	nodeReturnStmt
	nodeSelectStmt
	nodeSelectorExpr
	nodeSendStmt
	nodeSliceExpr
	nodeStarExpr
	nodeStructType
	nodeSwitchStmt
	nodeTypeAssertExpr
	nodeTypeSpec
	nodeTypeSwitchStmt
	nodeUnaryExpr
	nodeValueSpec

	nodeCategoriesCount

	// Categories below are not used inside scopedRuleSet yet
	// as categorizeNode will never produce them during the parsing.
	// They're required for Node.Is().

	nodeExpr // ast.Expr
	nodeStmt // ast.Stmt
)

func categorizeNode(n ast.Node) nodeCategory {
	switch n.(type) {
	case *ast.ArrayType:
		return nodeArrayType
	case *ast.AssignStmt:
		return nodeAssignStmt
	case *ast.BasicLit:
		return nodeBasicLit
	case *ast.BinaryExpr:
		return nodeBinaryExpr
	case *ast.BlockStmt:
		return nodeBlockStmt
	case *ast.BranchStmt:
		return nodeBranchStmt
	case *ast.CallExpr:
		return nodeCallExpr
	case *ast.CaseClause:
		return nodeCaseClause
	case *ast.ChanType:
		return nodeChanType
	case *ast.CommClause:
		return nodeCommClause
	case *ast.CompositeLit:
		return nodeCompositeLit
	case *ast.DeclStmt:
		return nodeDeclStmt
	case *ast.DeferStmt:
		return nodeDeferStmt
	case *ast.Ellipsis:
		return nodeEllipsis
	case *ast.EmptyStmt:
		return nodeEmptyStmt
	case *ast.ExprStmt:
		return nodeExprStmt
	case *ast.ForStmt:
		return nodeForStmt
	case *ast.FuncDecl:
		return nodeFuncDecl
	case *ast.FuncLit:
		return nodeFuncLit
	case *ast.FuncType:
		return nodeFuncType
	case *ast.GenDecl:
		return nodeGenDecl
	case *ast.GoStmt:
		return nodeGoStmt
	case *ast.Ident:
		return nodeIdent
	case *ast.IfStmt:
		return nodeIfStmt
	case *ast.ImportSpec:
		return nodeImportSpec
	case *ast.IncDecStmt:
		return nodeIncDecStmt
	case *ast.IndexExpr:
		return nodeIndexExpr
	case *ast.InterfaceType:
		return nodeInterfaceType
	case *ast.KeyValueExpr:
		return nodeKeyValueExpr
	case *ast.LabeledStmt:
		return nodeLabeledStmt
	case *ast.MapType:
		return nodeMapType
	case *ast.ParenExpr:
		return nodeParenExpr
	case *ast.RangeStmt:
		return nodeRangeStmt
	case *ast.ReturnStmt:
		return nodeReturnStmt
	case *ast.SelectStmt:
		return nodeSelectStmt
	case *ast.SelectorExpr:
		return nodeSelectorExpr
	case *ast.SendStmt:
		return nodeSendStmt
	case *ast.SliceExpr:
		return nodeSliceExpr
	case *ast.StarExpr:
		return nodeStarExpr
	case *ast.StructType:
		return nodeStructType
	case *ast.SwitchStmt:
		return nodeSwitchStmt
	case *ast.TypeAssertExpr:
		return nodeTypeAssertExpr
	case *ast.TypeSpec:
		return nodeTypeSpec
	case *ast.TypeSwitchStmt:
		return nodeTypeSwitchStmt
	case *ast.UnaryExpr:
		return nodeUnaryExpr
	case *ast.ValueSpec:
		return nodeValueSpec
	default:
		return nodeUnknown
	}
}

func categorizeNodeString(s string) nodeCategory {
	switch s {
	case "Expr":
		return nodeExpr
	case "Stmt":
		return nodeStmt
	}

	// Below is a switch from categorizeNode.
	switch s {
	case "ArrayType":
		return nodeArrayType
	case "AssignStmt":
		return nodeAssignStmt
	case "BasicLit":
		return nodeBasicLit
	case "BinaryExpr":
		return nodeBinaryExpr
	case "BlockStmt":
		return nodeBlockStmt
	case "BranchStmt":
		return nodeBranchStmt
	case "CallExpr":
		return nodeCallExpr
	case "CaseClause":
		return nodeCaseClause
	case "ChanType":
		return nodeChanType
	case "CommClause":
		return nodeCommClause
	case "CompositeLit":
		return nodeCompositeLit
	case "DeclStmt":
		return nodeDeclStmt
	case "DeferStmt":
		return nodeDeferStmt
	case "Ellipsis":
		return nodeEllipsis
	case "EmptyStmt":
		return nodeEmptyStmt
	case "ExprStmt":
		return nodeExprStmt
	case "ForStmt":
		return nodeForStmt
	case "FuncDecl":
		return nodeFuncDecl
	case "FuncLit":
		return nodeFuncLit
	case "FuncType":
		return nodeFuncType
	case "GenDecl":
		return nodeGenDecl
	case "GoStmt":
		return nodeGoStmt
	case "Ident":
		return nodeIdent
	case "IfStmt":
		return nodeIfStmt
	case "ImportSpec":
		return nodeImportSpec
	case "IncDecStmt":
		return nodeIncDecStmt
	case "IndexExpr":
		return nodeIndexExpr
	case "InterfaceType":
		return nodeInterfaceType
	case "KeyValueExpr":
		return nodeKeyValueExpr
	case "LabeledStmt":
		return nodeLabeledStmt
	case "MapType":
		return nodeMapType
	case "ParenExpr":
		return nodeParenExpr
	case "RangeStmt":
		return nodeRangeStmt
	case "ReturnStmt":
		return nodeReturnStmt
	case "SelectStmt":
		return nodeSelectStmt
	case "SelectorExpr":
		return nodeSelectorExpr
	case "SendStmt":
		return nodeSendStmt
	case "SliceExpr":
		return nodeSliceExpr
	case "StarExpr":
		return nodeStarExpr
	case "StructType":
		return nodeStructType
	case "SwitchStmt":
		return nodeSwitchStmt
	case "TypeAssertExpr":
		return nodeTypeAssertExpr
	case "TypeSpec":
		return nodeTypeSpec
	case "TypeSwitchStmt":
		return nodeTypeSwitchStmt
	case "UnaryExpr":
		return nodeUnaryExpr
	case "ValueSpec":
		return nodeValueSpec
	default:
		return nodeUnknown
	}
}
