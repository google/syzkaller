// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/google/syzkaller/pkg/aflow/journal"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
)

type Tool interface {
	create(*createContext) (tool.Tool, error)
}

type funcTool[Args, Results any] struct {
	// For logging/debugging.
	Name        string
	Description string
	Func        func(*Context, Args) (Results, error) `json:"-"`

	InputSchema  *jsonschema.Schema
	OutputSchema *jsonschema.Schema
}

func NewFuncTool[Args, Results any](name string, fn func(*Context, Args) (Results, error), description string) Tool {
	t, err := newFuncTool[Args, Results](name, fn, description)
	if err != nil {
		panic(err)
	}
	return t
}

func newFuncTool[Args, Results any](name string, fn func(*Context, Args) (Results, error), description string) (
	Tool, error) {
	inputSchema, err := schemaFor[Args]()
	if err != nil {
		return nil, err
	}
	outputSchema, err := schemaFor[Results]()
	if err != nil {
		return nil, err
	}
	return &funcTool[Args, Results]{
		Name:         name,
		Description:  description,
		Func:         fn,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
	}, nil
}

func (t *funcTool[Args, Results]) create(*createContext) (tool.Tool, error) {
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
			Args: convertToMap(args),
		})
		var zero Results
		if err != nil {
			return zero, err
		}
		if span.End != nil {
			//!!!
		}
		res, resErr := t.Func(ctx, args)
		_, err = ctx.journal.Append(&journal.EventToolResult{
			SpanEnd: journal.SpanEnd{
				Error: errorToString(resErr),
			},
			Results: convertToMap(res),
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
