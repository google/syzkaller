// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"testing"

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
