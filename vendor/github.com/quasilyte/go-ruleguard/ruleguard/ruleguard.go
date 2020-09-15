package ruleguard

import (
	"go/ast"
	"go/token"
	"go/types"
	"io"
)

type Context struct {
	Types  *types.Info
	Sizes  types.Sizes
	Fset   *token.FileSet
	Report func(rule GoRuleInfo, n ast.Node, msg string, s *Suggestion)
	Pkg    *types.Package
}

type Suggestion struct {
	From        token.Pos
	To          token.Pos
	Replacement []byte
}

func ParseRules(filename string, fset *token.FileSet, r io.Reader) (*GoRuleSet, error) {
	p := newRulesParser()
	return p.ParseFile(filename, fset, r)
}

func RunRules(ctx *Context, f *ast.File, rules *GoRuleSet) error {
	return newRulesRunner(ctx, rules).run(f)
}

type GoRuleInfo struct {
	// Filename is a file that defined this rule.
	Filename string
}

type GoRuleSet struct {
	universal *scopedGoRuleSet
	local     *scopedGoRuleSet
}

func MergeRuleSets(toMerge []*GoRuleSet) *GoRuleSet {
	return mergeRuleSets(toMerge)
}
