// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
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
	testFlow[struct{}, flowOutputs](t, nil,
		"tool faulty failed: error: hard error\nargs: map[CallError:false]",
		&LLMAgent{
			Name:        "smarty",
			Model:       "model",
			Reply:       "Reply",
			TaskType:    FormalReasoningTask,
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
		[]any{
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id0",
					Name: "faulty",
					Args: map[string]any{
						"CallError": true,
					},
				},
			},
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id0",
					Name: "faulty",
					Args: map[string]any{
						"CallError": false,
					},
				},
			},
		},
		nil,
	)
}

func TestToolLoopDetection(t *testing.T) {
	agent := &LLMAgent{Name: "test-agent"}
	args := map[string]any{"Query": "test"}

	// Record defaultLoopDetectionLimit identical calls.
	for range defaultLoopDetectionLimit {
		agent.recordToolCall("test-tool", args)
	}

	// The 4th call should be detected as a duplicate.
	call := &genai.FunctionCall{
		Name: "test-tool",
		Args: args,
	}
	err := agent.checkDuplicateCall(call)
	var badCallErr *badCallError
	require.ErrorAs(t, err, &badCallErr)
	require.Contains(t, err.Error(), "repeating the same tool call")

	// A different call should not be detected as a duplicate.
	diffCall := &genai.FunctionCall{
		Name: "diff-tool",
		Args: args,
	}
	err = agent.checkDuplicateCall(diffCall)
	require.NoError(t, err, "unexpected error on different call: %v", err)
}

func TestToolHistorySequentialLeak(t *testing.T) {
	args := map[string]any{"Q": "1"}
	toolExecutionCount := 0
	agent := &LLMAgent{
		Name:  "test-agent",
		Reply: "Done",
		Tools: []Tool{
			NewFuncTool("test-tool", func(ctx *Context, state struct{},
				args struct {
					Q string `jsonschema:"query string"`
				}) (struct{}, error) {
				toolExecutionCount++
				return struct{}{}, nil
			}, "description"),
		},
	}

	// Run 1 executes 3 parallel identical tool calls (filling history to loop limit).
	ctx1 := newTestContext(t, func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
		*genai.GenerateContentResponse, error) {
		if len(req) == 1 {
			return &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{{Content: &genai.Content{
					Role: string(genai.RoleModel),
					Parts: []*genai.Part{
						{FunctionCall: &genai.FunctionCall{ID: "c1", Name: "test-tool", Args: args}},
						{FunctionCall: &genai.FunctionCall{ID: "c2", Name: "test-tool", Args: args}},
						{FunctionCall: &genai.FunctionCall{ID: "c3", Name: "test-tool", Args: args}},
					},
				}}},
			}, nil
		}
		return &genai.GenerateContentResponse{
			Candidates: []*genai.Candidate{{Content: &genai.Content{
				Role:  string(genai.RoleModel),
				Parts: []*genai.Part{{Text: "Done"}},
			}}},
		}, nil
	})

	require.NoError(t, agent.execute(ctx1), "run 1 failed")

	// Run 2 is a completely fresh run and executes 1 tool call.
	ctx2 := newTestContext(t, func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
		*genai.GenerateContentResponse, error) {
		if len(req) == 1 {
			return &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{{Content: &genai.Content{
					Role: string(genai.RoleModel),
					Parts: []*genai.Part{
						{FunctionCall: &genai.FunctionCall{ID: "c4", Name: "test-tool", Args: args}},
					},
				}}},
			}, nil
		}
		return &genai.GenerateContentResponse{
			Candidates: []*genai.Candidate{{Content: &genai.Content{
				Role:  string(genai.RoleModel),
				Parts: []*genai.Part{{Text: "Done"}},
			}}},
		}, nil
	})

	require.NoError(t, agent.execute(ctx2), "run 2 failed")

	// Expected behavior: 3 calls in Run 1 + 1 call in Run 2 = 4 executions.
	// Buggy behavior: 1st call of Run 2 is incorrectly blocked by leaked history = only 3 executions.
	require.Equal(t, 4, toolExecutionCount, "state leak bug demonstrated! (one call was blocked by leaked history)")
}

func newTestContext(t *testing.T,
	generateContent func(string, *genai.GenerateContentConfig, []*genai.Content) (
		*genai.GenerateContentResponse, error)) *Context {
	stub := stubContext{
		timeNow:         time.Now,
		generateContent: generateContent,
	}
	cache, err := newTestCache(t, t.TempDir(), 0, time.Now)
	require.NoError(t, err, "failed to create test cache")
	ctx := context.WithValue(context.Background(), stubContextKey, &stub)
	return &Context{
		Context:     ctx,
		stubContext: stub,
		cache:       cache,
		state:       map[string]any{},
		onEvent:     func(span *trajectory.Span) error { return nil },
	}
}
