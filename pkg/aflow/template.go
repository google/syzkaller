// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/google/syzkaller/pkg/report/crash"
)

// formatTemplate formats template 'text' using the standard text/template logic.
// Panics on any errors, but these panics shouldn't happen if verifyTemplate
// was called for the template before.
func formatTemplate(text string, state map[string]any) string {
	templ, err := parseTemplate(text)
	if err != nil {
		panic(err)
	}
	w := new(bytes.Buffer)
	if err := templ.Execute(w, state); err != nil {
		panic(err)
	}
	return w.String()
}

// verifyTemplate checks that the template 'text' can be executed with the variables 'vars'.
// Returns the set of variables that are actually used in the template.
func verifyTemplate(text string, vars map[string]reflect.Type) (map[string]bool, error) {
	templ, err := parseTemplate(text)
	if err != nil {
		return nil, err
	}
	used := make(map[string]bool)
	walkTemplate(templ.Root, used, &err)
	if err != nil {
		return nil, err
	}
	vals := make(map[string]any)
	for name := range used {
		typ, ok := vars[name]
		if !ok {
			return nil, fmt.Errorf("input %v is not provided", name)
		}
		vals[name] = reflect.Zero(typ).Interface()
	}
	// Execute once just to make sure.
	if err := templ.Execute(io.Discard, vals); err != nil {
		return nil, err
	}
	return used, nil
}

// walkTemplate recursively walks template nodes collecting used variables.
// It does not handle all node types, but enough to support reasonably simple templates.
func walkTemplate(n parse.Node, used map[string]bool, errp *error) {
	if reflect.ValueOf(n).IsNil() {
		return
	}
	switch n := n.(type) {
	case *parse.ListNode:
		for _, c := range n.Nodes {
			walkTemplate(c, used, errp)
		}
	case *parse.IfNode:
		walkTemplate(n.Pipe, used, errp)
		walkTemplate(n.List, used, errp)
		walkTemplate(n.ElseList, used, errp)
	case *parse.RangeNode:
		walkTemplate(n.Pipe, used, errp)
		walkTemplate(n.List, used, errp)
		walkTemplate(n.ElseList, used, errp)
	case *parse.ActionNode:
		walkTemplate(n.Pipe, used, errp)
	case *parse.PipeNode:
		for _, c := range n.Decl {
			walkTemplate(c, used, errp)
		}
		for _, c := range n.Cmds {
			walkTemplate(c, used, errp)
		}
	case *parse.CommandNode:
		for _, c := range n.Args {
			walkTemplate(c, used, errp)
		}
	case *parse.FieldNode:
		if len(n.Ident) != 1 {
			noteError(errp, "compound values are not supported: .%v", strings.Join(n.Ident, "."))
		}
		used[n.Ident[0]] = true
	case *parse.VariableNode:
	case *parse.TextNode:
	case *parse.IdentifierNode:
	default:
		noteError(errp, "unhandled node type %T", n)
	}
}

func parseTemplate(prompt string) (*template.Template, error) {
	return template.New("").Option("missingkey=error").Funcs(templateFuncs).Parse(prompt)
}

var templateFuncs = template.FuncMap{
	"titleIsUAF":            titleIs(crash.KASANUseAfterFreeRead, crash.KASANUseAfterFreeWrite),
	"titleIsKASANNullDeref": titleIs(crash.KASANNullPtrDerefRead, crash.KASANNullPtrDerefWrite),
	"titleIsWarning":        titleIs(crash.Warning),
}

func titleIs(types ...crash.Type) func(string) bool {
	return func(title string) bool {
		return slices.Contains(types, crash.TitleToType(title))
	}
}
