// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"github.com/google/syzkaller/pkg/agent"
	"google.golang.org/adk/tool"
)

var Tool = agent.NewFuncTool(
	"codesearch",
	"code searching tool",
	func(ctx tool.Context, args args) result {
		return result{do(ctx, args.Action, args.Entity)}
	})

type args struct {
	Action string `json:"action" jsonschema:"Action to perform: search or define."`
	Entity string `json:"entity" jsonschema:"Entity to search for."`
}

type result struct {
	Results []string `json:"results" jsonschema:"List of matches."`
}

func do(ctx tool.Context, action, entity string) []string {
	return []string{"foo", "bar"}
}
