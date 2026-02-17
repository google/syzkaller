// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func mcpHandler(cfg *Config, cache *aflow.Cache) http.Handler {
	serv := mcp.NewServer(&mcp.Implementation{Name: "syzkaller", Version: "v1.0.0"}, nil)
	sessions := new(sync.Map) // Session ID string -> *Session.
	for tool, fn := range aflow.MCPTools {
		serv.AddTool(tool, toolHandler(cfg, workdir, cache, sessions, fn))
	}
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return serv
	}, &mcp.StreamableHTTPOptions{
		JSONResponse:   true,
		SessionTimeout: time.Hour,
	})
}

func toolHandler(cfg *Config, workdir string, cache *aflow.Cache, sessions *sync.Map,
	fn aflow.MCPToolFunc) mcp.ToolHandler {
	type Session struct {
		mu   sync.Mutex
		actx *aflow.Context
	}
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, err
		}
		anyS, _ := sessions.LoadOrStore(req.Session.ID(), &Session{})
		s := anyS.(*Session)
		// Serialize requests related to each session.
		// Unclear if mcp package allows concurrent requests within a sessions,
		// but we don't need them, and the aflow.Context is not thread-safe.
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.actx == nil {
			// Unclear if we can use the ctx as context. It may be per-request
			// context that's cancelled at the end of the current request.
			s.actx = aflow.NewMCPContext(context.Background(), workdir, cache, initState(cfg))
			go func() {
				req.Session.Wait()
				s.actx.Close()
				sessions.Delete(req.Session.ID())
			}()
		}
		return fn(s.actx, args)
	}
}
