// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"iter"
	"maps"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/session"
)

func NewFuncAction[Args, Results any](name string, fn func(*Context, Args) (Results, error)) Action {
	return newFuncAction[Args, Results](name, true, fn)
}

func newFuncAction[Args, Results any](name string, log bool, fn func(*Context, Args) (Results, error)) Action {
	a, err := newFuncActionImpl[Args, Results](name, log, fn)
	if err != nil {
		panic(err)
	}
	return a
}

func newFuncActionImpl[Args, Results any](name string, log bool, fn func(*Context, Args) (Results, error)) (
	Action, error) {
	return &funcAction[Args, Results]{
		name: name,
		fn:   fn,
		log:  log,
	}, nil
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
				args, err := convertFromMap[Args](maps.Collect(ictx.Session().State().All()))
				if err != nil {
					return err
				}
				if a.log {
					_, err = ctx.journal.Append(&journal.EventActionStart{
						SpanStart: journal.SpanStart{
							Name: a.name,
						},
					})
					if err != nil {
						return err
					}
				}
				res, fnErr := a.fn(ctx, args.(Args))
				resMap := convertToMap[Results](res)
				if a.log {
					_, err = ctx.journal.Append(&journal.EventActionEnd{
						SpanEnd: journal.SpanEnd{
							Error: errorToString(fnErr),
						},
						Results: resMap,
					})
					if err != nil {
						return err
					}
				}
				if fnErr != nil {
					return fnErr
				}
				for name, val := range resMap {
					if err := ictx.Session().State().Set(name, val); err != nil {
						return err
					}
				}
				return nil
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
