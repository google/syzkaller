package ruleguard

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/quasilyte/go-ruleguard/internal/mvdan.cc/gogrep"
	"github.com/quasilyte/go-ruleguard/ruleguard/goutil"
)

type rulesRunner struct {
	state *engineState

	ctx   *RunContext
	rules *goRuleSet

	importer *goImporter

	filename string
	src      []byte

	// A slice that is used to do a nodes keys sorting in renderMessage().
	sortScratch []string

	filterParams filterParams
}

func newRulesRunner(ctx *RunContext, state *engineState, rules *goRuleSet) *rulesRunner {
	importer := newGoImporter(state, goImporterConfig{
		fset:         ctx.Fset,
		debugImports: ctx.DebugImports,
		debugPrint:   ctx.DebugPrint,
	})
	rr := &rulesRunner{
		ctx:      ctx,
		importer: importer,
		rules:    rules,
		filterParams: filterParams{
			env:      state.env.GetEvalEnv(),
			importer: importer,
			ctx:      ctx,
		},
		sortScratch: make([]string, 0, 8),
	}
	rr.filterParams.nodeText = rr.nodeText
	return rr
}

func (rr *rulesRunner) nodeText(n ast.Node) []byte {
	from := rr.ctx.Fset.Position(n.Pos()).Offset
	to := rr.ctx.Fset.Position(n.End()).Offset
	src := rr.fileBytes()
	if (from >= 0 && from < len(src)) && (to >= 0 && to < len(src)) {
		return src[from:to]
	}
	// Fallback to the printer.
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, rr.ctx.Fset, n); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (rr *rulesRunner) fileBytes() []byte {
	if rr.src != nil {
		return rr.src
	}

	// TODO(quasilyte): re-use src slice?
	src, err := ioutil.ReadFile(rr.filename)
	if err != nil || src == nil {
		// Assign a zero-length slice so rr.src
		// is never nil during the second fileBytes call.
		rr.src = make([]byte, 0)
	} else {
		rr.src = src
	}
	return rr.src
}

func (rr *rulesRunner) run(f *ast.File) error {
	// TODO(quasilyte): run local rules as well.

	rr.filename = rr.ctx.Fset.Position(f.Pos()).Filename
	rr.filterParams.filename = rr.filename
	rr.collectImports(f)

	for _, rule := range rr.rules.universal.uncategorized {
		rule.pat.Match(f, func(m gogrep.MatchData) {
			rr.handleMatch(rule, m)
		})
	}

	if rr.rules.universal.categorizedNum != 0 {
		ast.Inspect(f, func(n ast.Node) bool {
			cat := categorizeNode(n)
			for _, rule := range rr.rules.universal.rulesByCategory[cat] {
				matched := false
				rule.pat.MatchNode(n, func(m gogrep.MatchData) {
					matched = rr.handleMatch(rule, m)
				})
				if matched {
					break
				}
			}
			return true
		})
	}

	return nil
}

func (rr *rulesRunner) reject(rule goRule, reason string, m gogrep.MatchData) {
	if rule.group != rr.ctx.Debug {
		return // This rule is not being debugged
	}

	pos := rr.ctx.Fset.Position(m.Node.Pos())
	rr.ctx.DebugPrint(fmt.Sprintf("%s:%d: [%s:%d] rejected by %s",
		pos.Filename, pos.Line, filepath.Base(rule.filename), rule.line, reason))

	type namedNode struct {
		name string
		node ast.Node
	}
	values := make([]namedNode, 0, len(m.Values))
	for name, node := range m.Values {
		values = append(values, namedNode{name: name, node: node})
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].name < values[j].name
	})

	for _, v := range values {
		name := v.name
		node := v.node
		var expr ast.Expr
		switch node := node.(type) {
		case ast.Expr:
			expr = node
		case *ast.ExprStmt:
			expr = node.X
		default:
			continue
		}

		typ := rr.ctx.Types.TypeOf(expr)
		typeString := "<unknown>"
		if typ != nil {
			typeString = typ.String()
		}
		s := strings.ReplaceAll(goutil.SprintNode(rr.ctx.Fset, expr), "\n", `\n`)
		rr.ctx.DebugPrint(fmt.Sprintf("  $%s %s: %s", name, typeString, s))
	}
}

func (rr *rulesRunner) handleMatch(rule goRule, m gogrep.MatchData) bool {
	if rule.filter.fn != nil {
		rr.filterParams.values = m.Values
		filterResult := rule.filter.fn(&rr.filterParams)
		if !filterResult.Matched() {
			rr.reject(rule, filterResult.RejectReason(), m)
			return false
		}
	}

	message := rr.renderMessage(rule.msg, m.Node, m.Values, true)
	node := m.Node
	if rule.location != "" {
		node = m.Values[rule.location]
	}
	var suggestion *Suggestion
	if rule.suggestion != "" {
		suggestion = &Suggestion{
			Replacement: []byte(rr.renderMessage(rule.suggestion, m.Node, m.Values, false)),
			From:        node.Pos(),
			To:          node.End(),
		}
	}
	info := GoRuleInfo{
		Group:    rule.group,
		Filename: rule.filename,
		Line:     rule.line,
	}
	rr.ctx.Report(info, node, message, suggestion)
	return true
}

func (rr *rulesRunner) collectImports(f *ast.File) {
	rr.filterParams.imports = make(map[string]struct{}, len(f.Imports))
	for _, spec := range f.Imports {
		s, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		rr.filterParams.imports[s] = struct{}{}
	}
}

func (rr *rulesRunner) renderMessage(msg string, n ast.Node, nodes map[string]ast.Node, truncate bool) string {
	var buf strings.Builder
	if strings.Contains(msg, "$$") {
		buf.Write(rr.nodeText(n))
		msg = strings.ReplaceAll(msg, "$$", buf.String())
	}
	if len(nodes) == 0 {
		return msg
	}

	rr.sortScratch = rr.sortScratch[:0]
	for name := range nodes {
		rr.sortScratch = append(rr.sortScratch, name)
	}
	sort.Slice(rr.sortScratch, func(i, j int) bool {
		return len(rr.sortScratch[i]) > len(rr.sortScratch[j])
	})

	for _, name := range rr.sortScratch {
		n := nodes[name]
		key := "$" + name
		if !strings.Contains(msg, key) {
			continue
		}
		buf.Reset()
		buf.Write(rr.nodeText(n))
		// Don't interpolate strings that are too long.
		var replacement string
		if truncate && buf.Len() > 60 {
			replacement = key
		} else {
			replacement = buf.String()
		}
		msg = strings.ReplaceAll(msg, key, replacement)
	}
	return msg
}
