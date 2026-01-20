// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genai"
)

func TestToolErrors(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolArgs struct {
		CallError bool `jsonschema:"call error"`
	}
	flows := make(map[string]*Flow)
	err := register[struct{}, flowOutputs]("test", "description", flows, []*Flow{
		{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Reply",
				Temperature: 0,
				Instruction: "Do something!",
				Prompt:      "Prompt",
				Tools: []Tool{
					NewFuncTool("faulty", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
						if args.CallError {
							return struct{}{}, BadCallError("you are wrong")
						}
						return struct{}{}, errors.New("hard error")
					}, "tool 1 description"),
				},
			},
		},
	})
	require.NoError(t, err)
	replySeq := 0
	stub := &stubContext{
		// nolint:dupl
		generateContent: func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			replySeq++
			switch replySeq {
			case 1:
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{
						Content: &genai.Content{
							Role: string(genai.RoleModel),
							Parts: []*genai.Part{
								{
									FunctionCall: &genai.FunctionCall{
										ID:   "id0",
										Name: "faulty",
										Args: map[string]any{
											"CallError": true,
										},
									},
								},
							}}}}}, nil
			case 2:
				assert.Equal(t, req[2], &genai.Content{
					Role: string(genai.RoleUser),
					Parts: []*genai.Part{
						{
							FunctionResponse: &genai.FunctionResponse{
								ID:   "id0",
								Name: "faulty",
								Response: map[string]any{
									"error": "you are wrong",
								},
							},
						}}})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{
						Content: &genai.Content{
							Role: string(genai.RoleModel),
							Parts: []*genai.Part{
								{
									FunctionCall: &genai.FunctionCall{
										ID:   "id0",
										Name: "faulty",
										Args: map[string]any{
											"CallError": false,
										},
									},
								},
							}}}}}, nil
			default:
				t.Fatal("unexpected LLM calls")
				return nil, nil
			}
		},
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	workdir := t.TempDir()
	cache, err := newTestCache(t, filepath.Join(workdir, "cache"), 0, time.Now)
	require.NoError(t, err)
	onEvent := func(span *trajectory.Span) error { return nil }
	_, err = flows["test"].Execute(ctx, "", workdir, nil, cache, onEvent)
	require.Equal(t, err.Error(), "tool faulty failed: error: hard error\nargs: map[CallError:false]")
}
