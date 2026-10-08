// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/require"
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
			Reply: "Reply",
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
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id0",
					Name: "faulty",
					Args: map[string]any{
						"CallError": true,
					},
				},
			},
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
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
	session := &agentSession{LLMAgent: &LLMAgent{Name: "test-agent"}}
	args := map[string]any{"Query": "test"}

	// The first 3 identical calls should be allowed.
	for range defaultLoopDetectionLimit {
		call := &backend.FunctionCall{Name: "test-tool", Args: args}
		err := session.recordAndCheckDuplicate(call)
		require.NoError(t, err)
	}

	// The 4th identical call should be detected as a duplicate.
	call := &backend.FunctionCall{Name: "test-tool", Args: args}
	err := session.recordAndCheckDuplicate(call)
	var badCallErr *badCallError
	require.ErrorAs(t, err, &badCallErr)
	require.Contains(t, err.Error(), "repeating the same tool call")

	// A different call should not be detected as a duplicate.
	diffCall := &backend.FunctionCall{Name: "diff-tool", Args: args}
	err = session.recordAndCheckDuplicate(diffCall)
	require.NoError(t, err, "unexpected error on different call: %v", err)
}

func TestToolLoopDetectionWarningOrder(t *testing.T) {
	session := &agentSession{LLMAgent: &LLMAgent{Name: "test-agent"}}
	tool := NewFuncTool("test-tool", func(ctx *Context, state struct{}, args struct {
		Query string `jsonschema:"query"`
	}) (struct{}, error) {
		return struct{}{}, nil
	}, "test tool")
	otherTool := NewFuncTool("other-tool", func(ctx *Context, state struct{}, args struct {
		Query string `jsonschema:"query"`
	}) (struct{}, error) {
		return struct{}{}, nil
	}, "other tool")
	tools := map[string]Tool{"test-tool": tool, "other-tool": otherTool}
	ctx := newTestContext(t, nil)
	args := map[string]any{"Query": "test"}

	for i := range defaultLoopDetectionLimit {
		call := &backend.FunctionCall{ID: fmt.Sprintf("call%d", i), Name: "test-tool", Args: args}
		err := session.callTools(ctx, tools, []*backend.FunctionCall{call})
		require.NoError(t, err)
	}

	// In the next turn, execute parallel calls where the second call is a duplicate.
	// All SYSTEM WARNING text parts must precede ALL FunctionResponse parts, and
	// the warning must explicitly mention the tool name.
	otherCall := &backend.FunctionCall{ID: "call-other", Name: "other-tool", Args: args}
	dupCall := &backend.FunctionCall{ID: "call-dup", Name: "test-tool", Args: args}
	err := session.callTools(ctx, tools, []*backend.FunctionCall{otherCall, dupCall})
	require.NoError(t, err)

	require.NotEmpty(t, session.req)
	lastMsg := session.req[len(session.req)-1].content
	require.Len(t, lastMsg.Parts, 3)
	require.Contains(t, lastMsg.Parts[0].Text, `SYSTEM WARNING for tool "test-tool":`)
	require.NotNil(t, lastMsg.Parts[1].FunctionResponse)
	require.Equal(t, "call-other", lastMsg.Parts[1].FunctionResponse.ID)
	require.NotNil(t, lastMsg.Parts[2].FunctionResponse)
	require.Equal(t, "call-dup", lastMsg.Parts[2].FunctionResponse.ID)
}

func TestToolHistorySequentialLeak(t *testing.T) {
	args := map[string]any{"Q": "1"}
	toolExecutionCount := 0
	agent := &LLMAgent{
		Name:  "test-agent",
		Model: "model",
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
	ctx1 := newTestContext(t, func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (
		*backend.GenerateResponse, error) {
		if len(req) == 1 {
			return &backend.GenerateResponse{
				Parts: []backend.Part{
					{FunctionCall: &backend.FunctionCall{ID: "c1", Name: "test-tool", Args: args}},
					{FunctionCall: &backend.FunctionCall{ID: "c2", Name: "test-tool", Args: args}},
					{FunctionCall: &backend.FunctionCall{ID: "c3", Name: "test-tool", Args: args}},
				},
			}, nil
		}
		return &backend.GenerateResponse{
			Parts: []backend.Part{{Text: "Done"}},
		}, nil
	})

	require.NoError(t, agent.execute(ctx1), "run 1 failed")

	// Run 2 is a completely fresh run and executes 1 tool call.
	ctx2 := newTestContext(t, func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (
		*backend.GenerateResponse, error) {
		if len(req) == 1 {
			return &backend.GenerateResponse{
				Parts: []backend.Part{
					{FunctionCall: &backend.FunctionCall{ID: "c4", Name: "test-tool", Args: args}},
				},
			}, nil
		}
		return &backend.GenerateResponse{
			Parts: []backend.Part{{Text: "Done"}},
		}, nil
	})

	require.NoError(t, agent.execute(ctx2), "run 2 failed")

	// Expected behavior: 3 calls in Run 1 + 1 call in Run 2 = 4 executions.
	// Buggy behavior: 1st call of Run 2 is incorrectly blocked by leaked history = only 3 executions.
	require.Equal(t, 4, toolExecutionCount, "state leak bug demonstrated! (one call was blocked by leaked history)")
}

func TestToolConsecutiveBadCallErrors(t *testing.T) {
	type toolArgs struct {
		Query string `jsonschema:"query"`
	}
	failTool := NewFuncTool("test-tool", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
		if args.Query == "ok" {
			return struct{}{}, nil
		}
		return struct{}{}, BadCallError("requested entity %q does not exist", args.Query)
	}, "test tool")
	tools := map[string]Tool{"test-tool": failTool}

	t.Run("warnings-and-hard-limit", func(t *testing.T) {
		session := &agentSession{LLMAgent: &LLMAgent{Name: "test-agent"}}
		ctx := newTestContext(t, nil)

		// First 3 distinct failing calls produce no SYSTEM WARNING.
		for i := 1; i <= defaultLoopDetectionLimit; i++ {
			call := &backend.FunctionCall{
				ID:   fmt.Sprintf("c%d", i),
				Name: "test-tool",
				Args: map[string]any{"Query": fmt.Sprintf("bad-%d", i)},
			}
			require.NoError(t, session.callTools(ctx, tools, []*backend.FunctionCall{call}))
			lastMsg := session.req[len(session.req)-1].content
			require.Len(t, lastMsg.Parts, 1)
			require.NotNil(t, lastMsg.Parts[0].FunctionResponse)
		}

		// A successful call resets the consecutive error counter.
		okCall := &backend.FunctionCall{
			ID:   "c-ok",
			Name: "test-tool",
			Args: map[string]any{"Query": "ok"},
		}
		require.NoError(t, session.callTools(ctx, tools, []*backend.FunctionCall{okCall}))
		require.Empty(t, session.toolErrorCounts["test-tool"])

		// Now fail up to hardLoopDetectionLimit - 1 and verify warnings appear after defaultLoopDetectionLimit.
		for i := 1; i < hardLoopDetectionLimit; i++ {
			call := &backend.FunctionCall{
				ID:   fmt.Sprintf("f%d", i),
				Name: "test-tool",
				Args: map[string]any{"Query": fmt.Sprintf("fail-%d", i)},
			}
			require.NoError(t, session.callTools(ctx, tools, []*backend.FunctionCall{call}))
			lastMsg := session.req[len(session.req)-1].content
			if i <= defaultLoopDetectionLimit {
				require.Len(t, lastMsg.Parts, 1)
			} else {
				require.Len(t, lastMsg.Parts, 2)
				require.Contains(t, lastMsg.Parts[0].Text, `SYSTEM WARNING for tool "test-tool":`)
			}
		}

		// The 6th consecutive failing call on a non-subagent returns a hard error.
		call6 := &backend.FunctionCall{
			ID:   "f6",
			Name: "test-tool",
			Args: map[string]any{"Query": "fail-6"},
		}
		err := session.callTools(ctx, tools, []*backend.FunctionCall{call6})
		require.ErrorContains(t, err, `agent got stuck in a loop making 6 consecutive failing calls to tool "test-tool"`)
	})

	t.Run("subagent-triggers-answer-now", func(t *testing.T) {
		type outStruct struct {
			Result string `jsonschema:"result"`
		}
		outputs := LLMOutputs[outStruct]()
		session := &agentSession{
			LLMAgent: &LLMAgent{
				Name:     "test-subagent",
				SubAgent: true,
				Outputs:  outputs,
			},
		}
		toolsWithOutputs := map[string]Tool{
			"test-tool":       failTool,
			llmSetResultsTool: outputs.tool,
		}
		ctx := newTestContext(t, nil)

		for i := 1; i <= hardLoopDetectionLimit; i++ {
			call := &backend.FunctionCall{
				ID:   fmt.Sprintf("f%d", i),
				Name: "test-tool",
				Args: map[string]any{"Query": fmt.Sprintf("mutated-%d", i)},
			}
			require.NoError(t, session.callTools(ctx, toolsWithOutputs, []*backend.FunctionCall{call}))
		}
		require.True(t, session.answerNow)
		require.Equal(t, answerNowIterations, session.answerNowLeft)
		lastMsg := session.req[len(session.req)-1].content
		require.Len(t, lastMsg.Parts, 2)
		require.Contains(t, lastMsg.Parts[0].Text, "All of your research tools are now disabled")

		// While answerNow is set or outputs are already populated, maybeCompressContext must be skipped.
		compressed, err := session.maybeCompressContext(ctx, "inst", 200_000)
		require.NoError(t, err)
		require.False(t, compressed)

		session.answerNow = false
		session.outputs = map[string]any{"Result": "done"}
		compressed, err = session.maybeCompressContext(ctx, "inst", 200_000)
		require.NoError(t, err)
		require.False(t, compressed)
	})
}

func newTestContext(t *testing.T,
	generateContent func(string, *backend.GenerateConfig, []*backend.Message) (
		*backend.GenerateResponse, error)) *Context {
	stub := stubContext{
		timeNow:         time.Now,
		generateContent: generateContent,
	}
	cache, err := newTestCache(t, t.TempDir(), 0, time.Now)
	require.NoError(t, err, "failed to create test cache")
	ctx := context.WithValue(context.Background(), stubContextKey, &stub)
	return &Context{
		Context:     ctx,
		provider:    &dummyProvider{},
		stubContext: stub,
		cache:       cache,
		state:       map[string]any{},
		onEvent:     func(span *trajectory.Span) error { return nil },
	}
}
