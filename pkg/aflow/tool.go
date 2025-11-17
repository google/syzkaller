// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"maps"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

type Tool interface {
	create(*createContext) (tool.Tool, error)
}

type funcTool[State, Args, Results any] struct {
	// For logging/debugging.
	Name        string
	Description string
	Func        func(*Context, State, Args) (Results, error)
}

func NewFuncTool[State, Args, Results any](name string, fn func(*Context, State, Args) (Results, error), description string) Tool {
	t, err := newFuncTool[State, Args, Results](name, fn, description)
	if err != nil {
		panic(err)
	}
	return t
}

func newFuncTool[State, Args, Results any](name string, fn func(*Context, State, Args) (Results, error), description string) (
	Tool, error) {
	return &funcTool[State, Args, Results]{
		Name:        name,
		Description: description,
		Func:        fn,
	}, nil
}

func (t *funcTool[State, Args, Results]) create(*createContext) (tool.Tool, error) {
	cfg := functiontool.Config{
		Name:        t.Name,
		Description: t.Description,
	}
	toolFn := func(tctx tool.Context, args Args) (Results, error) {
		ctx := tctx.Value(contextKey).(*Context)
		span, err := ctx.journal.Append(&journal.EventToolCall{
			SpanStart: journal.SpanStart{
				Name: t.Name,
			},
			Args: convertToMap[Args](args),
		})
		var zero Results
		if err != nil {
			return zero, err
		}
		if span.End != nil {
			//!!!
		}
		//!!! verify flow for state args
		state, err := convertFromMap[State](maps.Collect(tctx.State().All()))
		if err != nil {
			return zero, err
		}
		res, resErr := t.Func(ctx, state.(State), args)
		_, err = ctx.journal.Append(&journal.EventToolResult{
			SpanEnd: journal.SpanEnd{
				Error: errorToString(resErr),
			},
			Results: convertToMap[Results](res),
		})
		if resErr != nil {
			err = resErr
		}
		return res, err
	}
	return functiontool.New(cfg, toolFn)
}

// TODO
type AgentTool struct{}
