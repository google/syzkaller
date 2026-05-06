// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

type Action interface {
	verify(*verifyContext)
	execute(*Context) error
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
