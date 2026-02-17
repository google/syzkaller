// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
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
	MCPTools[tool] = handler
}

func registerMCPAction[Args, Results any](a *funcAction[Args, Results]) {
	tool := &mcp.Tool{
		Name:         a.name,
		Description:  a.name,
		InputSchema:  mustSchemaFor[struct{}](),
		OutputSchema: mustSchemaFor[struct{}](),
	}
	handler := func(ctx *Context, args map[string]any) (*mcp.CallToolResult, error) {
		err := a.execute(ctx)
		reply := &mcp.CallToolResult{
			StructuredContent: struct{}{},
		}
		return reply, err
	}
	MCPTools[tool] = handler
}
