// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/adk/model"
	"google.golang.org/genai"
)

func TestFuncAction(t *testing.T) {
	type flowInputs struct {
		InFoo int
		InBar string
		InBaz string
	}
	type flowOutputs struct {
		OutFoo string
		OutBar int
	}
	type firstFuncInputs struct {
		InFoo int
		InBar string
	}
	type firstFuncOutputs struct {
		TmpFuncOutput string
		OutBar        int
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
						Reply:       "OutFoo",
						Temperature: 0,
						Instruction: "You are smarty.",
						Prompt:      "Prompt: {{.InBaz}} {{.TmpFuncOutput}}",
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
	inputs := map[string]any{
		"InFoo": 10,
		"InBar": "bar",
		"InBaz": "baz",
	}
	workdir := t.TempDir()
	onEvent := func(span *trajectory.Span) error {
		return nil
	}
	var stubTime time.Time
	stub := &stubContext{
		timeNow: func() time.Time {
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
	res, err := flows["test-flow"].Execute(ctx, true, workdir, inputs, onEvent)
	require.NoError(t, err)
	_ = res
}
