// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/assert"
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
		&LLMAgent{
			Reply: "Reply",
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
		[]any{
			// Main agent calls the tool sub-agent.
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id0",
					Name: "researcher",
					Args: map[string]any{
						"Question": "What do you think?",
					},
				},
			},
			// Sub-agent calls own tool.
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id1",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 1",
					},
				},
			},
			// Sub-agent returns result.
			backend.Part{Text: "Nothing."},
			// Repeat the same one more time.
			backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id2",
					Name: "researcher",
					Args: map[string]any{
						"Question": "But really?",
					},
				},
			},
			backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id3",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 2",
					},
				},
			},
			// Now model input token overflow.
			backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id4",
					Name: "researcher-tool",
					Args: map[string]any{
						"Something": "subtool input 3",
					},
				},
			},
			&backend.InputTokenOverflowError{Err: fmt.Errorf("the input token count exceeds the maximum")},
			backend.Part{Text: "Still nothing."},
			// Main returns result.
			backend.Part{Text: "YES"},
		},
		nil,
	)
}

func TestLLMToolMaxIters(t *testing.T) {
	type outputs struct {
		Reply string
	}
	type toolArgs struct {
		Arg int `jsonschema:"something"`
	}
	replies := []any{
		// Main agent calls the tool sub-agent.
		&backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id0",
				Name: "researcher",
				Args: map[string]any{
					"Question": "What do you think?",
				},
			},
		},
	}
	// Sub-agent calls own tool maxLLMIterations times.
	for i := range maxLLMIterations {
		replies = append(replies, &backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id1",
				Name: "researcher-tool",
				Args: map[string]any{
					"Arg": i,
				},
			},
		})
	}
	replies = append(replies,
		// Sub-agent returns result.
		backend.Part{Text: "Nothing."},
		// Main returns result.
		backend.Part{Text: "YES"},
	)
	testFlow[struct{}, outputs](t, nil, map[string]any{"Reply": "YES"},
		&LLMAgent{
			Reply: "Reply",
			Tools: []Tool{
				&LLMTool{
					Name:        "researcher",
					Model:       "sub-agent-model",
					TaskType:    FormalReasoningTask,
					Description: "researcher description",
					Instruction: "researcher instruction",
					Tools: []Tool{
						NewFuncTool("researcher-tool", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
							return struct{}{}, nil
						}, "researcher-tool description"),
					},
				},
			},
		},
		replies,
		nil,
	)
}
