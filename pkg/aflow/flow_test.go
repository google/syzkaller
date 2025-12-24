// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/adk/model"
	"google.golang.org/genai"
)

func TestFuncAction(t *testing.T) {
	type flowInputs struct {
		InFoo int    `json:"in-foo"`
		InBar string `json:"in-bar"`
		InBaz string `json:"in-baz"`
	}
	type flowOutputs struct {
		OutFoo string `json:"out-foo"`
		OutBar int    `json:"out-bar"`
	}
	type firstFuncInputs struct {
		InFoo int    `json:"in-foo"`
		InBar string `json:"in-bar"`
	}
	type firstFuncOutputs struct {
		TmpFuncOutput string `json:"func-output"`
		OutBar        int    `json:"out-bar"`
	}
	type secondFuncInputs struct {
		//InFoo int `json:"in-foo"`
	}
	type secondFuncOutputs struct {
		//TmpFuncOutput int    `json:"func-output"`
		//OutBar        string `json:"out-bar"`
	}
	flows := make(map[string]*Flow)
	err := register[flowInputs, flowOutputs]("test", "description", flows, []*Flow{
		&Flow{
			Name: "flow",
			Root: &Pipeline{
				Actions: []Action{
					NewFuncAction("func-action",
						func(ctx *Context, args firstFuncInputs) (firstFuncOutputs, error) {
							assert.Equal(t, args.InFoo, 10)
							assert.Equal(t, args.InBar, "bar")
							return firstFuncOutputs{
								TmpFuncOutput: "func-output",
								OutBar:        42,
							}, nil
						}),
					&LLMAgent{
						Name:        "smarty",
						OutputKey:   "out-foo",
						Temperature: 0,
						Instruction: "You are smarty.",
						Prompt:      "Prompt: {in-baz} {func-output}",
					},
					NewFuncAction("func-action",
						func(*Context, secondFuncInputs) (secondFuncOutputs, error) {
							return secondFuncOutputs{}, nil
						}),
				},
			},
		},
	})
	require.NoError(t, err)
	inputs := flowInputs{
		InFoo: 10,
		InBar: "bar",
	}
	workdir := t.TempDir()
	onEvent := func(ev *journal.Event) error {
		return nil
	}
	var stubTime time.Time
	stub := &stubContext{
		now: func() time.Time {
			stubTime = stubTime.Add(time.Second)
			return stubTime
		},
		generateContent: func(req *model.LLMRequest) (*model.LLMResponse, error) {
			return &model.LLMResponse{
				Content: genai.NewContentFromText("hello, world!", genai.RoleModel),
			}, nil
		},
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	res, err := flows["test-flow"].Execute(ctx, true, workdir, inputs, nil, onEvent)
	require.NoError(t, err)
	_ = res
}
