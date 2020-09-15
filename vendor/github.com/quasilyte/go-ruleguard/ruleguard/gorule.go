package ruleguard

import (
	"go/types"

	"github.com/quasilyte/go-ruleguard/internal/mvdan.cc/gogrep"
)

type scopedGoRuleSet struct {
	uncategorized   []goRule
	categorizedNum  int
	rulesByCategory [nodeCategoriesCount][]goRule
}

type goRule struct {
	filename   string
	severity   string
	pat        *gogrep.Pattern
	msg        string
	location   string
	suggestion string
	filters    map[string]submatchFilter
}

type submatchFilter struct {
	typePred    func(typeQuery) bool
	textPred    func(string) bool
	pure        bool3
	constant    bool3
	addressable bool3
}

type typeQuery struct {
	x   types.Type
	ctx *Context
}
