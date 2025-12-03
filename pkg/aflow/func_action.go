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
	a, err := newFuncAction[Args, Results](name, fn)
	if err != nil {
		panic(err)
	}
	return a
}

func newFuncAction[Args, Results any](name string, fn func(*Context, Args) (Results, error)) (Action, error) {
	return &funcAction[Args, Results]{
		Name: name,
		Func: fn,
	}, nil
}

type funcAction[Args, Results any] struct {
	Name string
	Func func(*Context, Args) (Results, error)
}

func (a *funcAction[Args, Results]) create(cctx *createContext) (agent.Agent, error) {
	return agent.New(agent.Config{
		Name: cctx.actionName(a.Name, ""),
		Run: func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			ctx := ictx.Value(contextKey).(*Context)
			run := func(ictx agent.InvocationContext) error {
				args, err := convertFromMap[Args](maps.Collect(ictx.Session().State().All()))
				if err != nil {
					return err
				}
				_, err = ctx.journal.Append(&journal.EventActionStart{
					SpanStart: journal.SpanStart{
						Name: a.Name,
					},
				})
				if err != nil {
					return err
				}
				res, resErr := a.Func(ctx, args.(Args))
				resMap := convertToMap[Results](res)
				_, err = ctx.journal.Append(&journal.EventActionEnd{
					SpanEnd: journal.SpanEnd{
						Error: errorToString(resErr),
					},
					Results: resMap,
				})
				if resErr != nil {
					err = resErr
				}
				if err != nil {
					return err
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
					yield(nil, fmt.Errorf("%v: %w", a.Name, err))
				}
			}
		},
	})
}

func (a *funcAction[Args, Results]) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(a.Name, "Name", a.Name)
	for name := range foreachFieldOf[Args]() {
		vctx.requireInput(a.Name, name)
	}
	for name := range foreachFieldOf[Results]() {
		vctx.provideOutput(a.Name, name, false)
	}
}
