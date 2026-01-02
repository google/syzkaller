// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"iter"
	"maps"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/session"
)

func NewFuncAction[Args, Results any](name string, fn func(*Context, Args) (Results, error)) Action {
	return newFuncAction[Args, Results](name, true, fn)
}

func newFuncAction[Args, Results any](name string, log bool, fn func(*Context, Args) (Results, error)) Action {
	return &funcAction[Args, Results]{
		name: name,
		fn:   fn,
		log:  log,
	}
}

type funcAction[Args, Results any] struct {
	name string
	fn   func(*Context, Args) (Results, error)
	log  bool
}

func (a *funcAction[Args, Results]) create(cctx *createContext) (agent.Agent, error) {
	return agent.New(agent.Config{
		Name: cctx.actionName(a.name, ""),
		Run: func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			ctx := ictx.Value(contextKey).(*Context)
			run := func(ictx agent.InvocationContext) error {
				args, err := convertFromMap[Args](ctx.state)
				if err != nil {
					return err
				}
				span := &trajectory.Span{
					Type: trajectory.SpanAction,
					Name: a.name,
				}
				if a.log {
					if err := ctx.startSpan(span); err != nil {
						return err
					}
				}
				res, fnErr := a.fn(ctx, args)
				span.Results = convertToMap(res)
				maps.Insert(ctx.state, maps.All(span.Results))
				if a.log {
					if err := ctx.finishSpan(span, fnErr); err != nil {
						return err
					}
				}
				return fnErr
			}
			return func(yield func(*session.Event, error) bool) {
				if err := run(ictx); err != nil {
					yield(nil, fmt.Errorf("%v: %w", a.name, err))
				}
			}
		},
	})
}

func (a *funcAction[Args, Results]) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(a.name, "Name", a.name)
	requireInputs[Args](vctx, a.name)
	provideOutputs[Results](vctx, a.name)
}
