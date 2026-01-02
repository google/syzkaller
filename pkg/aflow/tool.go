// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

type Tool interface {
	create(*createContext) (tool.Tool, error)
	verify(*verifyContext)
}

type funcTool[State, Args, Results any] struct {
	// For logging/debugging.
	Name        string
	Description string
	Func        func(*Context, State, Args) (Results, error)
}

func NewFuncTool[State, Args, Results any](name string, fn func(*Context, State, Args) (Results, error),
	description string) Tool {
	t, err := newFuncTool[State, Args, Results](name, fn, description)
	if err != nil {
		panic(err)
	}
	return t
}

func newFuncTool[State, Args, Results any](name string, fn func(*Context, State, Args) (Results, error),
	description string) (Tool, error) {
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
		var zero Results
		span := &trajectory.Span{
			Type: trajectory.SpanTool,
			Name: t.Name,
			Args: convertToMap(args),
		}
		if err := ctx.startSpan(span); err != nil {
			return zero, err
		}
		state, err := convertFromMap[State](ctx.state)
		if err != nil {
			return zero, err
		}
		res, resErr := t.Func(ctx, state, args)
		span.Results = convertToMap(res)
		err = ctx.finishSpan(span, resErr)
		return res, err
	}
	return functiontool.New(cfg, toolFn)
}

func (t *funcTool[State, Args, Results]) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(t.Name, "Name", t.Name)
	vctx.requireNotEmpty(t.Name, "Description", t.Description)
	requireInputs[State](vctx, t.Name)
	requireJsonSchema[Args](vctx, t.Name, "args")
	requireJsonSchema[Results](vctx, t.Name, "results")
}
