// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"iter"

	"github.com/google/jsonschema-go/jsonschema"
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
	inputSchema, err := schemaFor[Args]()
	if err != nil {
		return nil, err
	}
	outputSchema, err := schemaFor[Results]()
	if err != nil {
		return nil, err
	}
	return &funcAction[Args, Results]{
		Name:           name,
		Func:           fn,
		InputSchema:    inputSchema,
		OutputSchema:   outputSchema,
		extractInputs:  extractFromState[Args],
		collectOutputs: storeToState[Results],
	}, nil
}

type funcAction[Args, Results any] struct {
	// For logging/debugging.
	Name string
	Func func(*Context, Args) (Results, error) `json:"-"`

	InputSchema    *jsonschema.Schema
	OutputSchema   *jsonschema.Schema
	extractInputs  func(session.State) (any, error)
	collectOutputs func(session.State, any) error
}

func (a *funcAction[Args, Results]) create(cctx *createContext) (agent.Agent, error) {
	return agent.New(agent.Config{
		Name: cctx.actionName(a.Name, ""),
		Run: func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			ctx := ictx.Value(contextKey).(*Context)
			run := func(ictx agent.InvocationContext) error {
				args, err := a.extractInputs(ictx.Session().State())
				if err != nil {
					return err
				}
				_, err = ctx.journal.Append(&journal.EventActionStart{
					SpanStart: journal.SpanStart{
						Name: a.Name,
					},
					Args: convertToMap(args),
				})
				if err != nil {
					return err
				}
				res, resErr := a.Func(ctx, args.(Args))
				_, err = ctx.journal.Append(&journal.EventActionEnd{
					SpanEnd: journal.SpanEnd{
						Error: errorToString(resErr),
					},
					Results: convertToMap(res),
				})
				if resErr != nil {
					err = resErr
				}
				if err != nil {
					return err
				}
				if err := a.collectOutputs(ictx.Session().State(), res); err != nil {
					return err
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
