// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var Tool = aflow.NewFuncTool("codesearch", do,
	// TODO: extend the description, it's important for LLMs.
	"code searching tool",
)

type args struct {
	Action string `json:"action" jsonschema:"Action to perform: search or define."`
	Entity string `json:"entity" jsonschema:"Entity to search for."`
}

type result struct {
	Results []string `json:"results" jsonschema:"List of matches."`
}

func do(ctx *aflow.Context, args args) (result, error) {
	return result{[]string{"foo", "bar"}}, nil
}
