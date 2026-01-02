// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/genai"
)

// NewFuncTool creates a new tool based on a custom function that an LLM agent can use.
// Name and description are important since they are passed to an LLM agent.
// Args and Results must be structs with fields commented with aflow tag,
// comments are also important since they are passed to the LLM agent.
// Args are accepted from the LLM agent on the tool invocation, Results are returned
// to the LLM agent. State fields are taken from the current execution state
// (they are not exposed to the LLM agent).
func NewFuncTool[State, Args, Results any](name string, fn func(*Context, State, Args) (Results, error),
	description string) Tool {
	return &funcTool[State, Args, Results]{
		Name:        name,
		Description: description,
		Func:        fn,
	}
}

type funcTool[State, Args, Results any] struct {
	Name        string
	Description string
	Func        func(*Context, State, Args) (Results, error)
}

func (t *funcTool[State, Args, Results]) declaration() *genai.FunctionDeclaration {
	return &genai.FunctionDeclaration{
		Name:                 t.Name,
		Description:          t.Description,
		ParametersJsonSchema: mustSchemaFor[Args](),
		ResponseJsonSchema:   mustSchemaFor[Results](),
	}
}

func (t *funcTool[State, Args, Results]) execute(ctx *Context, args map[string]any) (map[string]any, error) {
	state, err := convertFromMap[State](ctx.state, false)
	if err != nil {
		return nil, err
	}
	a, err := convertFromMap[Args](args, true)
	if err != nil {
		return nil, err
	}
	span := &trajectory.Span{
		Type: trajectory.SpanTool,
		Name: t.Name,
		Args: args,
	}
	if err := ctx.startSpan(span); err != nil {
		return nil, err
	}
	res, err := t.Func(ctx, state, a)
	span.Results = convertToMap(res)
	err = ctx.finishSpan(span, err)
	return span.Results, err
}

func (t *funcTool[State, Args, Results]) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(t.Name, "Name", t.Name)
	ctx.requireNotEmpty(t.Name, "Description", t.Description)
	requireSchema[Args](ctx, t.Name, "Args")
	requireSchema[Results](ctx, t.Name, "Results")
	requireInputs[State](ctx, t.Name)
}
