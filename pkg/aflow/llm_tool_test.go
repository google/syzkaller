// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/genai"
)

func TestLLMTool(t *testing.T) {
	type inputs struct {
		Input int
	}
	type outputs struct {
		Reply string
	}
	type toolArgs struct {
		Something string `jsonschema:"something"`
	}
	testFlow[inputs, outputs](t, map[string]any{"Input": 42}, map[string]any{"Reply": "YES"},
		Pipeline(
			&LLMAgent{
				Name:        "smarty",
				Model:       "model",
				TaskType:    FormalReasoningTask,
				Reply:       "Reply",
				Instruction: "Do something!",
				Prompt:      "Prompt",
				Tools: []Tool{
					&LLMTool{
						Name:        "researcher",
						Model:       "sub-agent-model",
						TaskType:    FormalReasoningTask,
						Description: "researcher description",
						Instruction: "researcher instruction",
						Tools: []Tool{
							NewFuncTool("researcher-tool", func(ctx *Context, state inputs, args toolArgs) (struct{}, error) {
								// State passed all the way from the workflow inputs.
								assert.Equal(t, state.Input, 42)
								assert.True(t, strings.HasPrefix(args.Something, "subtool input"),
									"args.Something=%q", args.Something)
								return struct{}{}, nil
							}, "researcher-tool description"),
						},
					},
				},
			},
		),
		[]any{
			// Main agent calls the tool sub-agent.
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id0",
					Name: "researcher",
					Args: map[string]any{
						"Question": "What do you think?",
					},
				},
			},
			// Sub-agent calls own tool.
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id1",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 1",
					},
				},
			},
			// Sub-agent returns result.
			genai.NewPartFromText("Nothing."),
			// Repeat the same one more time.
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id2",
					Name: "researcher",
					Args: map[string]any{
						"Question": "But really?",
					},
				},
			},
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id3",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 2",
					},
				},
			},
			// Now model input token overflow.
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id4",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 3",
					},
				},
			},
			genai.APIError{
				Code:    http.StatusBadRequest,
				Message: "The input token count exceeds the maximum number of tokens allowed 1048576.",
			},
			genai.NewPartFromText("Still nothing."),
			// Main returns result.
			genai.NewPartFromText("YES"),
		},
	)
}
