// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"

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

// BadCallError creates an error that means that LLM made a bad tool call,
// the provided message will be returned to the LLM as an error,
// instead of failing the whole workflow.
func BadCallError(message string, args ...any) error {
	return &badCallError{fmt.Errorf(message, args...)}
}

type badCallError struct {
	error
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
	state, err := convertFromMap[State](ctx.state, false, false)
	if err != nil {
		return nil, err
	}
	// We parse args in non-strict mode too.
	// LLM shouldn't provide excessive args, but they are known to mess up things
	// in all possible ways occasionally. Generally we want to handle such cases
	// in some way, rather than fail the whole workflow. We could reply to it
	// with an error about this, but it's unclear if the additional round-trip
	// worth it, it already provided all the actual arguments.
	a, err := convertFromMap[Args](args, false, true)
	if err != nil {
		return nil, err
	}
	res, err := t.Func(ctx, state, a)
	return convertToMap(res), err
}

func (t *funcTool[State, Args, Results]) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(t.Name, "Name", t.Name)
	ctx.requireNotEmpty(t.Name, "Description", t.Description)
	requireSchema[Args](ctx, t.Name, "Args")
	requireSchema[Results](ctx, t.Name, "Results")
	requireInputs[State](ctx, t.Name)
}
