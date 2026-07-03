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
				&LLMTool[inputs, DefaultLLMArgs]{
					Name:        "researcher",
					Model:       "sub-agent-model",
					TaskType:    FormalReasoningTask,
					Description: "researcher description",
					Instruction: "researcher instruction",
					Prompt:      `{{.Question}}`,
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
			backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id_out1",
					Name: "set-results",
					Args: map[string]any{
						"Answer": "Nothing.",
					},
				},
			},
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
			backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id_out2",
					Name: "set-results",
					Args: map[string]any{
						"Answer": "Still nothing.",
					},
				},
			},
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
	for i := range defaultMaxLLMIterations {
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
	// The sub-agent hits maxLLMIterations and attempts to answer now.
	// We provide an invalid reply so that it fails to produce structured output,
	// causing the sub-agent loop to end and return BadCallError.
	replies = append(replies, &backend.Part{Text: "I give up!"})
	// The main agent receives the BadCallError as a tool error response and continues,
	// providing its final reply without terminating the flow.
	replies = append(replies, &backend.Part{Text: "Sub-agent reached limit, but flow continues!"})
	testFlow[struct{}, outputs](t, nil,
		map[string]any{"Reply": "Sub-agent reached limit, but flow continues!"},
		&LLMAgent{
			Reply: "Reply",
			Tools: []Tool{
				&LLMTool[struct{}, DefaultLLMArgs]{
					Name:        "researcher",
					Model:       "sub-agent-model",
					TaskType:    FormalReasoningTask,
					Description: "researcher description",
					Instruction: "researcher instruction",
					Prompt:      `{{.Question}}`,
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

func TestLLMToolValidation(t *testing.T) {
	type outputs struct {
		Reply string
	}

	type testResult struct {
		Answer string `jsonschema:"Answer"`
	}

	testFlow[struct{}, outputs](t, nil, map[string]any{"Reply": "YES"},
		&LLMAgent{
			Reply: "Reply",
			Tools: []Tool{
				&StructuredLLMTool[struct{}, DefaultLLMArgs, testResult]{
					Name:        "researcher",
					Model:       "sub-agent-model",
					TaskType:    FormalReasoningTask,
					Description: "researcher description",
					Instruction: "researcher instruction",
					Prompt:      `{{.Question}}`,
					Outputs: ValidatedLLMToolOutputs[testResult, struct{}, DefaultLLMArgs](
						func(ctx *Context, state struct{}, args DefaultLLMArgs, res testResult) (testResult, error) {
							assert.Equal(t, "What do you think?", args.Question)
							if res.Answer == "Bad reply" {
								return res, BadCallError("this reply is bad")
							}
							return res, nil
						},
					),
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
			// Sub-agent returns bad result.
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id1",
					Name: "set-results",
					Args: map[string]any{
						"Answer": "Bad reply",
					},
				},
			},
			// Sub-agent returns good result.
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id2",
					Name: "set-results",
					Args: map[string]any{
						"Answer": "Good reply",
					},
				},
			},
			// Main returns result.
			backend.Part{Text: "YES"},
		},
		nil,
	)
}

func TestStructuredLLMToolWithJudge(t *testing.T) {
	type outputs struct {
		Reply string
	}
	type testResult struct {
		Answer string `jsonschema:"Answer"`
	}
	type toolResults struct {
		Res int `jsonschema:"res"`
	}

	testFlow[struct{}, outputs](t, nil, map[string]any{"Reply": "RECOVERED_AFTER_JUDGE_STOP"},
		&LLMAgent{
			Reply: "Reply",
			Tools: []Tool{
				&StructuredLLMTool[struct{}, DefaultLLMArgs, testResult]{
					Name:        "researcher",
					Model:       "sub-agent-model",
					TaskType:    FormalReasoningTask,
					Description: "researcher description",
					Instruction: "researcher instruction",
					Prompt:      `{{.Question}}`,
					Tools: []Tool{
						NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
							return toolResults{42}, nil
						}, "ticker"),
					},
					Judge: &LLMJudge{
						Name:               "test-judge",
						Model:              "judge-model",
						MinIterations:      1,
						EvaluationInterval: 1,
						Instruction:        "Judge the history",
					},
				},
			},
		},
		[]any{
			// Turn 0: Main agent calls researcher subagent.
			&backend.Part{
				FunctionCall: &backend.FunctionCall{
					ID:   "id0",
					Name: "researcher",
					Args: map[string]any{
						"Question": "What is the answer?",
					},
				},
			},
			// Turn 1: Subagent calls tick tool (iteration 0).
			createToolCallResponse(50, "tick_id1", "tick"),
			// Handle subsequent calls: Subagent iteration 1, Judge evaluation, and Main agent final turn.
			func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (*backend.GenerateResponse, error) {
				if cfg.SystemInstruction != nil && len(cfg.SystemInstruction.Parts) > 0 &&
					strings.Contains(cfg.SystemInstruction.Parts[0].Text, "Judge the history") {
					if req[len(req)-1].Parts[0].FunctionResponse == nil {
						return &backend.GenerateResponse{
							Parts: []backend.Part{
								{FunctionCall: &backend.FunctionCall{
									Name: "set-results",
									Args: map[string]any{"Stop": true, "Reason": "oscillation detected in researcher"},
								}},
							},
						}, nil
					}
					return &backend.GenerateResponse{Parts: []backend.Part{{Text: "Done"}}}, nil
				}
				for _, part := range req[len(req)-1].Parts {
					if part.FunctionResponse != nil && part.FunctionResponse.Name == "researcher" {
						errStr, _ := part.FunctionResponse.Response["error"].(string)
						assert.Contains(t, errStr, "subagent \"researcher\" was stopped by judge: oscillation detected in researcher")
						return &backend.GenerateResponse{Parts: []backend.Part{{Text: "RECOVERED_AFTER_JUDGE_STOP"}}}, nil
					}
				}
				return createToolCallResponse(50, "tick_id2", "tick"), nil
			},
		},
		nil,
	)
}
