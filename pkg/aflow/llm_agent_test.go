// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLLMRetryLimit(t *testing.T) {
	ctx := NewTestContext(t)
	err0 := fmt.Errorf("api error")
	retryErr := &backend.RetryError{Delay: time.Second, Err: err0, IsExponential: true}

	var delays []time.Duration
	var tries int

	ctx.stubContext = stubContext{
		timeNow: time.Now,
		sleep: func(d time.Duration) {
			delays = append(delays, d)
		},
		generateContent: func(model string, cfg *backend.GenerateConfig,
			req []*backend.Message) (*backend.GenerateResponse, error) {
			tries++
			return nil, retryErr
		},
	}
	ctx.provider = &dummyProvider{}

	agent := &LLMAgent{
		Name:  "test-agent",
		Model: "model1",
	}

	cfg := &backend.GenerateConfig{}
	_, err := agent.generateContent(ctx, cfg, nil, 0, "model1", nil)

	require.ErrorIs(t, err, err0)
	require.Equal(t, maxLLMRetryIters+1, tries)

	expected := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		64 * time.Second,
		128 * time.Second,
	}
	for len(expected) < maxLLMRetryIters {
		expected = append(expected, 3*time.Minute)
	}
	require.Equal(t, expected, delays)
}

func TestTokenCompression(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolResults struct {
		ResFoo int `jsonschema:"foo"`
	}
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Reply:          "Reply",
			compressTokens: 100,
			Tools: []Tool{
				NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
					return toolResults{123}, nil
				}, "logic ticker"),
			},
		},
		[]any{
			// 1. Initial request. Return a tool call and establish the anchor token count.
			createToolCallResponse(150, "id1", "tick"),
			// 2. Second request. Return another tool call and report total tokens 260.
			// This means delta = 260 - 150 = 110. Since 110 > compressTokensValue (100), compression triggers!
			createToolCallResponse(260, "id2", "tick"),
			// 3. The loop detects threshold exceeded and invokes compressContext (Flash model).
			// We return the compressed summary.
			&backend.GenerateResponse{
				UsageMetadata: &backend.UsageMetadata{
					InputTokens:  260,
					OutputTokens: 10,
				},
				Parts: []backend.Part{{Text: "compressed summary"}},
			},
			// 4. The main agent resumes with the truncated history. We finish the workflow.
			func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (*backend.GenerateResponse, error) {
				// Assert that the history was correctly truncated!
				assert.Equal(t, 2, len(req), "History should be truncated to just Anchor and Summary")

				// Assert Anchor Message remains untouched.
				assert.Equal(t, "Prompt", req[0].Parts[0].Text)

				// Assert Summary is correctly formatted.
				assert.Equal(t, "Here is the summary of the previous execution history:\n\ncompressed summary",
					req[1].Parts[0].Text)
				return &backend.GenerateResponse{
					UsageMetadata: &backend.UsageMetadata{
						InputTokens:  20, // tokens dropped after compression
						OutputTokens: 10,
					},
					Parts: []backend.Part{{Text: "Done"}},
				}, nil
			},
		},
		nil,
	)
}

// TestTokenCompressionResetsHistory verifies that when context compression occurs,
// the duplicate tool call detection history is reset.
// This is tested by making 3 identical calls (which fills the history up to the limit),
// triggering compression, and then asserting that the 4th identical call is allowed
// (whereas it would be blocked as a duplicate if history wasn't reset).
func TestTokenCompressionResetsHistory(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolResults struct {
		ResFoo int `jsonschema:"foo"`
	}
	toolExecutionCount := 0
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Reply:          "Reply",
			compressTokens: 100,
			Tools: []Tool{
				NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
					toolExecutionCount++
					return toolResults{123}, nil
				}, "logic ticker"),
			},
		},
		[]any{
			createToolCallResponse(150, "id1", "tick"),
			createToolCallResponse(150, "id2", "tick"),
			createToolCallResponse(260, "id3", "tick"),
			&backend.GenerateResponse{
				UsageMetadata: &backend.UsageMetadata{
					InputTokens:  260,
					OutputTokens: 10,
				},
				Parts: []backend.Part{{Text: "compressed summary"}},
			},
			createToolCallResponse(50, "id4", "tick"),
			backend.Part{Text: "Done"},
		},
		nil,
	)
	require.Equal(t, 4, toolExecutionCount, "toolHistory was not reset on compression!")
}

func createToolCallResponse(tokens int, id, name string) *backend.GenerateResponse {
	return &backend.GenerateResponse{
		UsageMetadata: &backend.UsageMetadata{
			InputTokens:  tokens,
			OutputTokens: 10,
		},
		Parts: []backend.Part{
			{FunctionCall: &backend.FunctionCall{ID: id, Name: name}},
		},
	}
}

func TestSetResultsToolIsNotLast(t *testing.T) {
	type flowOutputs struct {
		Reply  string
		Result int
	}
	type flowResults struct {
		Result int `jsonschema:"Result"`
	}
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done", "Result": 42},
		&LLMAgent{
			Reply:   "Reply",
			Outputs: LLMOutputs[flowResults](),
			Tools: []Tool{
				NewFuncTool("tool", func(ctx *Context, state struct{}, args struct{}) (struct{}, error) {
					return struct{}{}, nil
				}, "tool"),
			},
		},
		[]any{
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "tool"}},
			backend.Part{Text: "Done"},
		},
		nil,
	)
}

func TestOnlyStructuredOutputs(t *testing.T) {
	type flowOutputs struct {
		Result int
	}
	type flowResults struct {
		Result int `jsonschema:"Result"`
	}
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Result": 42},
		&LLMAgent{
			Outputs: LLMOutputs[flowResults](),
		},
		[]any{
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
		},
		nil,
	)
}

func TestNilToolArg(t *testing.T) {
	type flowResults struct {
		Result string
	}
	type toolArgs struct {
		Optional *int `jsonschema:"An optional arg."`
	}
	testFlow[struct{}, flowResults](t, nil,
		map[string]any{"Result": "Result"},
		&LLMAgent{
			Reply:       "Result",
			Instruction: "Instructions: use the provided tool {{.toolSwissKnife}} for something.",
			Tools: []Tool{
				NewFuncTool("swiss-knife", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
					require.Equal(t, args.Optional, nil)
					return struct{}{}, nil
				}, "tool description"),
			},
		},
		[]any{
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "swiss-knife", Args: map[string]any{"Optional": nil}}},
			backend.Part{Text: "Result"},
		},
		nil,
	)
}

func TestToolInPrompt(t *testing.T) {
	type flowResults struct {
		Ignored string
	}
	testFlow[struct{}, flowResults](t, nil, map[string]any{"Ignored": "Ignored"},
		&LLMAgent{
			Reply:       "Ignored",
			Instruction: "Use {{.toolSwissKnife}}",
			Prompt:      "Please call {{.toolSwissKnife}} now.",
			Tools: []Tool{
				NewFuncTool("swiss-knife", func(ctx *Context, state struct{}, args struct{}) (struct{}, error) {
					return struct{}{}, nil
				}, "description"),
			},
		},
		[]any{
			backend.Part{Text: "Ignored"},
		},
		nil,
	)
}

func TestAgentRegistrationErrors(t *testing.T) {
	testRegistrationError[struct{}, struct{}](t,
		`flow test: action smarty: Instruction: template: :1: function "NonExistentFoo" not defined`,
		&Flow{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Result",
				TaskType:    FormalReasoningTask,
				Instruction: "{{NonExistentFoo}}",
				Prompt:      "Prompt",
			},
		})
	testRegistrationError[struct{}, struct{}](t,
		`flow test: action smarty: bad tool name "BadTool_name", expect ^[a-z][a-z0-9-]+[a-z0-9]$`,
		&Flow{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Result",
				TaskType:    FormalReasoningTask,
				Instruction: "Instruction",
				Prompt:      "Prompt",
				Tools: []Tool{
					NewFuncTool("BadTool_name", func(ctx *Context, state struct{}, args struct{}) (struct{}, error) {
						return struct{}{}, nil
					}, "tool description"),
				},
			},
		})
	testRegistrationError[struct{}, struct{ Result string }](t,
		`flow test: action smarty: tool "swiss-knife" is duplicated`,
		&Flow{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Result",
				TaskType:    FormalReasoningTask,
				Instruction: "Instruction",
				Prompt:      "Prompt",
				Tools: []Tool{
					NewFuncTool("swiss-knife", func(ctx *Context, state struct{}, args struct{}) (struct{}, error) {
						return struct{}{}, nil
					}, "tool description"),
					NewFuncTool("swiss-knife", func(ctx *Context, state struct{}, args struct{}) (struct{}, error) {
						return struct{}{}, nil
					}, "tool description"),
				},
			},
		})
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action smarty: both Reply and ValidatedReply are specified",
		&Flow{
			Root: &LLMAgent{
				Name:  "smarty",
				Model: "model",
				Reply: "foo",
				ValidatedReply: LLMReply("bar", func(*Context, struct{}, string) (string, error) {
					return "", nil
				}),
				TaskType:    FormalReasoningTask,
				Instruction: "Instructions",
				Prompt:      "Initial Prompt",
			},
		})
}

func TestOutputOverflow(t *testing.T) {
	type flowResults struct {
		Result string
		Output int
	}
	overflowErr := &backend.OutputTokenOverflowError{Err: errors.New("MAX_TOKENS")}
	testFlow[struct{}, flowResults](t, nil, "MAX_TOKENS",
		&LLMAgent{
			Reply: "Result",
			Outputs: LLMOutputs[struct {
				Output int `jsonschema:"Some output."`
			}](),
		},
		[]any{
			// First return few overflow errors. The framework should reduce amount of thinking.
			overflowErr,
			overflowErr,
			overflowErr,
			// But in the end the invocation succeeds.
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "set-results", Args: map[string]any{"Output": 42}}},
			// The framework should reset the thinking level back to HIGH for the new request.
			// The request fails even with minimal level of thinking.
			overflowErr,
			overflowErr,
			overflowErr,
			overflowErr,
		},
		nil,
	)
}

func TestValidatedLLMOutputs(t *testing.T) {
	type flowOutputs struct {
		Result    int
		Unrelated int
	}
	type flowInputs struct {
		StateValue int
		Unrelated  int
	}
	type subState struct {
		StateValue int
	}
	type flowResults struct {
		Result int `jsonschema:"Result"`
	}
	testFlow[flowInputs, flowOutputs](t, map[string]any{"StateValue": 42, "Unrelated": 123},
		map[string]any{"Result": 43, "Unrelated": 123},
		&LLMAgent{
			Outputs: ValidatedLLMOutputs[flowResults](
				func(ctx *Context, state subState, args flowResults) (flowResults, error) {
					if state.StateValue != 42 {
						return args, fmt.Errorf("bad state value: %v", state.StateValue)
					}
					if args.Result == 42 {
						return args, BadCallError("result cannot be 42")
					}
					if args.Result == 100 {
						args.Result = 43
					}
					return args, nil
				}),
			Prompt: "Initial Prompt with {{.StateValue}} and {{.Unrelated}}",
		},
		[]any{
			// First try returns an invalid result.
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
			// Second try returns a result that is modified by the validation function.
			&backend.Part{FunctionCall: &backend.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 100}}},
		},
		nil,
	)
}

func TestValidatedLLMOutputsVerify(t *testing.T) {
	type flowInputs struct {
		StateValue int
	}
	type flowOutputs struct {
		Result int
	}
	type missingState struct {
		MissingValue int
	}
	type flowResults struct {
		Result int `jsonschema:"Result"`
	}

	testRegistrationError[flowInputs, flowOutputs](t,
		"flow test-test: action set-results: no input MissingValue, available inputs: [StateValue]",
		&Flow{
			Name: "test",
			Root: &LLMAgent{
				Name:  "smarty",
				Model: "model",
				Outputs: ValidatedLLMOutputs[flowResults](
					func(ctx *Context, state missingState, args flowResults) (flowResults, error) {
						return args, nil
					}),
				TaskType:    FormalReasoningTask,
				Instruction: "Instructions",
				Prompt:      "Initial Prompt",
			},
		})
}

func TestValidatedLLMReply(t *testing.T) {
	testFlow[struct{ StateValue int }, struct{ Result string }](
		t, map[string]any{"StateValue": 42}, map[string]any{"Result": "changed-reply"},
		&LLMAgent{
			ValidatedReply: LLMReply("Result", func(ctx *Context, state struct{ StateValue int }, reply string) (string, error) {
				require.Equal(t, 42, state.StateValue)
				switch reply {
				case "reply1":
					return "", BadCallError("please don't reply like this")
				case "reply2":
					return "changed-reply", nil
				default:
					t.Fatalf("unexpected reply %q", reply)
					return "", nil
				}
			}),
		},
		[]any{
			backend.Part{Text: "reply1"},
			backend.Part{Text: "reply2"},
		},
		nil,
	)
}

// TestModelFallbackTrajectory verifies that when a workflow is configured with a model pool (fallback list),
// and the primary model fails (e.g. returns quota limit error), the workflow engine successfully falls back
// to the backup model and executes. It also verifies that only the successful fallback model is recorded
// in the finished LLM span of the execution trajectory.
func TestModelFallbackTrajectory(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Name:     "smarty",
			Model:    "fallback-pool",
			Reply:    "Reply",
			TaskType: FormalReasoningTask,
		},
		[]any{
			func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (
				*backend.GenerateResponse, error) {
				if model == "model1" {
					return nil, errors.New("model1 failed (quota limit)")
				}
				if model == "model2" {
					return &backend.GenerateResponse{
						Parts: []backend.Part{{Text: "Done"}},
					}, nil
				}
				return nil, fmt.Errorf("unexpected model %q", model)
			},
		},
		nil,
	)
}

func TestLLMAgentMaxIterations(t *testing.T) {
	type outputs struct {
		Reply string
	}
	type toolArgs struct {
		Arg int `jsonschema:"something"`
	}
	replies := []any{}
	for i := range 3 {
		replies = append(replies, &backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id1",
				Name: "some-tool",
				Args: map[string]any{
					"Arg": i,
				},
			},
		})
	}
	testFlow[struct{}, outputs](t, nil,
		"agent reached max iterations limit (3)",
		&LLMAgent{
			Reply:         "Reply",
			MaxIterations: 3,
			Tools: []Tool{
				NewFuncTool("some-tool", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
					return struct{}{}, nil
				}, "some-tool description"),
			},
		},
		replies,
		nil,
	)
}
