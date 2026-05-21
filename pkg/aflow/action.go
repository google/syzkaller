// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

type Action interface {
	verify(*verifyContext)
	execute(*Context) error
	info() *ActionNode
}

// ActionNode provides info about workflow for SVG visualization by tools/syz-aflow.
type ActionNode struct {
	Type     string
	Name     string
	Branch   string
	Children []*ActionNode
}

type pipeline struct {
	// These actions are invoked sequentially,
	// but dataflow across actions is specified by their use
	// of variables in args/instructions/prompts.
	actions []Action
}

func Pipeline(actions ...Action) *pipeline {
	return &pipeline{
		actions: actions,
	}
}

func (p *pipeline) execute(ctx *Context) error {
	for _, sub := range p.actions {
		if err := sub.execute(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *pipeline) verify(ctx *verifyContext) {
	for _, a := range p.actions {
		a.verify(ctx)
	}
}

func (p *pipeline) info() *ActionNode {
	n := &ActionNode{
		Type: "Pipeline",
		Name: "Pipeline",
	}
	for _, a := range p.actions {
		n.Children = append(n.Children, a.info())
	}
	return n
}
