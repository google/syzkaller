// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

type Action interface {
	verify(*verifyContext)
	execute(*Context) error
}

type Pipeline struct {
	// These actions are invoked sequentially,
	// but dataflow across actions is specified by their use
	// of variables in args/instructions/prompts.
	Actions []Action
}

func NewPipeline(actions ...Action) *Pipeline {
	return &Pipeline{
		Actions: actions,
	}
}

func (p *Pipeline) execute(ctx *Context) error {
	for _, sub := range p.Actions {
		if err := sub.execute(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) verify(ctx *verifyContext) {
	for _, a := range p.Actions {
		a.verify(ctx)
	}
}
