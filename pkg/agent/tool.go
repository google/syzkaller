// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
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
	Func        func(tool.Context, Args) Results `json:"-"`

	InputSchema  *jsonschema.Schema
	OutputSchema *jsonschema.Schema
}

func NewFuncTool[Args, Results any](name, description string, fn func(tool.Context, Args) Results) Tool {
	inputSchema, err := jsonschema.For[Args](nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create json schema for args type: %w", err))
	}
	outputSchema, err := jsonschema.For[Results](nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create json schema for results type: %w", err))
	}
	return &funcTool[Args, Results]{
		Name:         name,
		Description:  description,
		Func:         fn,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
	}
}

func (t *funcTool[Args, Results]) create(*createContext) (tool.Tool, error) {
	cfg := functiontool.Config{
		Name:        t.Name,
		Description: t.Description,
	}
	return functiontool.New(cfg, t.Func)
}

// TODO
type AgentTool struct{}
