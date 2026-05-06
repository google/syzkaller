// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Export all tools (and actions as tools) for tools/syz-mcp to serve them over MCP protocol.
var MCPTools = map[*mcp.Tool]MCPToolFunc{}

type MCPToolFunc func(ctx *Context, args map[string]any) (*mcp.CallToolResult, error)

func NewMCPContext(ctx context.Context, workdir string, cache *Cache, state map[string]any) *Context {
	return &Context{
		Context: ctx,
		Workdir: osutil.Abs(workdir),
		cache:   cache,
		state:   state,
		onEvent: func(span *trajectory.Span) error { return nil },
		stubContext: stubContext{
			timeNow: time.Now,
		},
	}
}

func registerMCPTool[State, Args, Results any](t *funcTool[State, Args, Results]) {
	tool := &mcp.Tool{
		Name:         t.Name,
		Description:  t.Description,
		InputSchema:  mustSchemaFor[Args](),
		OutputSchema: mustSchemaFor[Results](),
	}
	handler := func(ctx *Context, args map[string]any) (*mcp.CallToolResult, error) {
		res, err := t.execute(ctx, args)
		reply := &mcp.CallToolResult{
			StructuredContent: res,
		}
		if err != nil {
			if callErr := new(badCallError); !errors.As(err, &callErr) {
				return nil, err
			}
			reply.SetError(err)
		}
		return reply, nil
	}
	registerMCP(tool, handler)
}

func registerMCPAction[Args, Results any](a *funcAction[Args, Results]) {
	tool := &mcp.Tool{
		Name:         a.name,
		Description:  a.name,
		InputSchema:  mustSchemaFor[struct{}](),
		OutputSchema: uncheckedSchemaFor[Results](),
	}
	handler := func(ctx *Context, args map[string]any) (*mcp.CallToolResult, error) {
		err := a.execute(ctx)
		if err != nil {
			return nil, err
		}
		res, err := convertFromMap[Results](ctx.state, false, false)
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{
			StructuredContent: res,
		}, nil
	}
	registerMCP(tool, handler)
}

var (
	registerMCPTools = true
	mcpToolNames     = map[string]bool{}
)

func registerMCP(tool *mcp.Tool, handler MCPToolFunc) {
	if !registerMCPTools || tool.Name == llmSetResultsTool {
		return
	}
	tool.Name = strings.ReplaceAll(tool.Name, "-", "_")
	if mcpToolNames[tool.Name] {
		panic(fmt.Sprintf("MCP tool %q is already registered", tool.Name))
	}
	mcpToolNames[tool.Name] = true
	MCPTools[tool] = handler
}

func init() {
	NewFuncTool("session-initializer", func(ctx *Context, state struct{}, args struct {
		ReproSyz  string `jsonschema:"syzkaller program that reproduces the bug."`
		ReproOpts string `jsonschema:"syzkaller program execution options."`
		ReproC    string `jsonschema:"C program that reproduces the bug."`
	}) (struct{}, error) {
		ctx.state["ReproSyz"] = args.ReproSyz
		ctx.state["ReproOpts"] = args.ReproOpts
		ctx.state["ReproC"] = args.ReproC
		return struct{}{}, nil
	}, `
The tool populates session state for other tools/actions to use.
It is supposed to be called first, and substitutes input workflow arguments in MCP mode.
`)
}
