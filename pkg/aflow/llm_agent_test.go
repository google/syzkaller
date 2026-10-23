// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
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

	// Verify that a zero Delay still sleeps for at least 1 second.
	retryErr = &backend.RetryError{Delay: 0, Err: err0, IsExponential: false}
	delays = nil
	tries = 0
	_, err = agent.generateContent(ctx, cfg, nil, 0, "model1", nil)
	require.ErrorIs(t, err, err0)
	require.Equal(t, maxLLMRetryIters+1, tries)
	require.Len(t, delays, maxLLMRetryIters)
	for _, d := range delays {
		require.Equal(t, time.Second, d)
	}
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
			// 1. Initial request: establish the anchor token count (150) and return a tool call with a thought.
			createToolCallResponseWithSig(150, 60, "id1", "tick", []byte("original-sig-1")),
			// 2. Second request: total tokens exceed anchor + compressTokens (150 + 100), triggering compression.
			// id2 (10 output + 30 thought tokens) fits in preserveHistoryTokens (50).
			createToolCallResponseWithSig(270, 30, "id2", "tick", []byte("original-sig-2")),
			// 3. The loop detects threshold exceeded and invokes compressContext (Flash model),
			// followed by the main agent resuming with the truncated history.
			func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (*backend.GenerateResponse, error) {
				if model == string(backend.LightweightModel) {
					// Summarizer invocation: verify single user message with XML tags and thoughts from id1.
					require.Equal(t, 1, len(req), "Summarizer should receive a single user message")
					require.Equal(t, backend.RoleUser, req[0].Role)
					text := req[0].Parts[0].Text
					require.Contains(t, text, "<initial_prompt>\n[user]:\nPrompt\n\n</initial_prompt>")
					_, history, found := strings.Cut(text, "<execution_history>")
					require.True(t, found, "missing <execution_history>")
					require.NotContains(t, history, "Prompt\n", "anchor prompt must not be part of execution history")
					require.Contains(t, history, "<thought>\nthinking about id1\n</thought>")
					require.NotContains(t, text, "thinking about id2")
					require.Contains(t, history, "</execution_history>")
					require.Empty(t, req[0].Parts[0].ThoughtSignature, "thought signatures must be cleared for summarizer")
					return &backend.GenerateResponse{
						UsageMetadata: &backend.UsageMetadata{
							InputTokens:  260,
							OutputTokens: 10,
						},
						Parts: []backend.Part{{Text: "compressed summary"}},
					}, nil
				}
				// Main agent resumed with the truncated history: Anchor + Summary + Preserved Suffix.
				require.Equal(t, 4, len(req), "History should be Anchor, Summary, and preserved suffix")
				require.Equal(t, "Prompt", req[0].Parts[0].Text)
				require.Equal(t, compressedHistoryPrefix+"compressed summary", req[1].Parts[0].Text)
				require.Equal(t, backend.RoleModel, req[2].Role)
				require.Len(t, req[2].Parts, 2, "thought part should be kept in preserved suffix")
				require.True(t, req[2].Parts[0].Thought)
				require.Equal(t, "thinking about id2", req[2].Parts[0].Text)
				require.Equal(t, []byte("original-sig-2"), req[2].Parts[0].ThoughtSignature,
					"preserved thought in suffix should keep its thought signature")
				require.Equal(t, "id2", req[2].Parts[1].FunctionCall.ID)
				require.Equal(t, []byte("original-sig-2"), req[2].Parts[1].ThoughtSignature,
					"preserved function call in suffix should keep its thought signature")
				require.Equal(t, backend.RoleUser, req[3].Role)
				require.Len(t, req[3].Parts, 2)
				require.Equal(t, compressedHistoryReminder, req[3].Parts[0].Text)
				require.Equal(t, "id2", req[3].Parts[1].FunctionResponse.ID)
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

func createToolCallResponseWithSig(tokens, thoughtTokens int, id, name string, sig []byte) *backend.GenerateResponse {
	return &backend.GenerateResponse{
		UsageMetadata: &backend.UsageMetadata{
			InputTokens:          tokens,
			OutputTokens:         10,
			OutputThoughtsTokens: thoughtTokens,
		},
		Parts: []backend.Part{
			{Thought: true, Text: "thinking about " + id, ThoughtSignature: sig},
			{FunctionCall: &backend.FunctionCall{ID: id, Name: name}, ThoughtSignature: sig},
		},
	}
}

// TestTokenCompressionResetsHistory verifies that when context compression occurs,
// duplicate tool call detection drops summarized calls (id1, id2) while retaining
// calls that remain in the preserved suffix (id3).
// After compression, id4 and id5 are allowed (bringing the suffix + post-compression
// count for "tick" to 3: id3, id4, id5), while id6 is blocked as the 4th duplicate call.
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
			createToolCallResponse(50, "id5", "tick"),
			createToolCallResponse(50, "id6", "tick"),
			backend.Part{Text: "Done"},
		},
		nil,
	)
	require.Equal(t, 5, toolExecutionCount, "expected id1..id5 to execute and id6 to be blocked as duplicate")
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
				Instruction: "Instructions",
				Prompt:      "Initial Prompt",
			},
		})
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action smarty: Candidates > 1 is not supported with Judge",
		&Flow{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Result",
				Instruction: "Instructions",
				Prompt:      "Initial Prompt",
				Candidates:  2,
				Judge: &LLMJudge{
					Name:               "judge",
					Model:              "model",
					EvaluationInterval: 1,
					MinIterations:      1,
					Instruction:        "Judge",
				},
			},
		})
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action smarty: Candidates > 1 is not supported with Advisor",
		&Flow{
			Root: &LLMAgent{
				Name:        "smarty",
				Model:       "model",
				Reply:       "Result",
				Instruction: "Instructions",
				Prompt:      "Initial Prompt",
				Candidates:  2,
				Advisor: &LLMAdvisor{
					Name:               "advisor",
					Model:              "model",
					EvaluationInterval: 1,
					MinIterations:      1,
					Instruction:        "Advise",
				},
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
			Name:  "smarty",
			Model: "fallback-pool",
			Reply: "Reply",
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

type maxIterationsToolArgs struct {
	Arg int `jsonschema:"something"`
}

// maxIterationsAgent returns an agent with a tool that fails if called after
// the agent ran out of iterations (i.e. if a disabled tool call is executed).
func maxIterationsAgent(maxIterations int) *LLMAgent {
	return &LLMAgent{
		MaxIterations: maxIterations,
		Tools: []Tool{
			NewFuncTool("some-tool", func(ctx *Context, state struct{}, args maxIterationsToolArgs) (
				struct{}, error) {
				if args.Arg >= maxIterations {
					return struct{}{}, fmt.Errorf("disabled tool executed")
				}
				return struct{}{}, nil
			}, "some-tool description"),
		},
	}
}

// maxIterationsReplies returns toolCalls replies calling some-tool with distinct arguments
// starting from first.
func maxIterationsReplies(first, toolCalls int) []any {
	var replies []any
	for i := range toolCalls {
		replies = append(replies, &backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id1",
				Name: "some-tool",
				Args: map[string]any{
					"Arg": first + i,
				},
			},
		})
	}
	return replies
}

// TestLLMAgentMaxIterations checks that a main agent that may not provide partial answers
// fails on reaching the iteration limit.
func TestLLMAgentMaxIterations(t *testing.T) {
	type outputs struct {
		Reply string
	}
	const maxIterations = 3
	agent := maxIterationsAgent(maxIterations)
	agent.Reply = "Reply"
	testFlow[struct{}, outputs](t, nil,
		"agent reached max iterations limit (3)",
		agent,
		maxIterationsReplies(0, maxIterations),
		nil,
	)
}

// TestLLMAgentMaxIterationsNoAnswer checks that a main agent that may provide partial answers
// is asked to wrap up on reaching the iteration limit, and fails only if it does not provide
// an answer within answerNowIterations more iterations.
func TestLLMAgentMaxIterationsNoAnswer(t *testing.T) {
	type outputs struct {
		Reply string
	}
	const maxIterations = 3
	agent := maxIterationsAgent(maxIterations)
	agent.Reply = "Reply"
	agent.AllowPartialResults = true
	replies := maxIterationsReplies(0, maxIterations)
	// The agent ignores the wrap-up order and keeps calling (now disabled) tools.
	replies = append(replies, maxIterationsReplies(maxIterations, answerNowIterations)...)
	testFlow[struct{}, outputs](t, nil,
		fmt.Sprintf("agent reached max iterations limit (%v)", maxIterations),
		agent,
		replies,
		nil,
	)
}

func TestLLMAgentAllowPartialResults(t *testing.T) {
	type agentOutputs struct {
		Verdict string `jsonschema:"verdict"`
	}
	type outputs struct {
		Reply   string
		Verdict string
	}
	type toolArgs struct {
		Arg int `jsonschema:"something"`
	}
	testFlow[struct{}, outputs](t, nil,
		convertToMap(outputs{
			Reply:   "Partial reply",
			Verdict: "partial",
		}),
		&LLMAgent{
			Reply:               "Reply",
			Outputs:             LLMOutputs[agentOutputs](),
			MaxIterations:       2,
			AllowPartialResults: true,
			Tools: []Tool{
				NewFuncTool("some-tool", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
					return struct{}{}, nil
				}, "some-tool description"),
			},
		},
		[]any{
			// Iteration 0 and 1: agent calls research tool until hitting MaxIterations=2.
			&backend.Part{FunctionCall: &backend.FunctionCall{
				ID:   "id1",
				Name: "some-tool",
				Args: map[string]any{"Arg": 0},
			}},
			&backend.Part{FunctionCall: &backend.FunctionCall{
				ID:   "id2",
				Name: "some-tool",
				Args: map[string]any{"Arg": 1},
			}},
			// Wrap-up turn 1: agent tries calling disabled research tool.
			&backend.Part{FunctionCall: &backend.FunctionCall{
				ID:   "id3",
				Name: "some-tool",
				Args: map[string]any{"Arg": 2},
			}},
			// Wrap-up turn 2: agent calls set-results.
			&backend.Part{FunctionCall: &backend.FunctionCall{
				ID:   "id_out",
				Name: "set-results",
				Args: map[string]any{"Verdict": "partial"},
			}},
			// Wrap-up turn 3: agent provides final text reply.
			&backend.Part{Text: "Partial reply"},
		},
		nil,
	)
}

func TestLLMAgentMaxIterationsReplyNow(t *testing.T) {
	type outputs struct {
		Reply string
	}
	const maxIterations = 3
	agent := maxIterationsAgent(maxIterations)
	agent.Reply = "Reply"
	agent.AllowPartialResults = true
	replies := append(maxIterationsReplies(0, maxIterations),
		// Attempt 1: ignores the order to wrap up and calls a disabled tool.
		&backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id_disabled",
				Name: "some-tool",
				Args: map[string]any{"Arg": 100},
			},
		},
		// Attempt 2: provides the final reply.
		&backend.Part{Text: "Partial strategy based on what I found so far."},
	)
	testFlow[struct{}, outputs](t, nil,
		map[string]any{"Reply": "Partial strategy based on what I found so far."},
		agent,
		replies,
		nil,
	)
}

func TestLLMAgentMaxIterationsSetResultsNow(t *testing.T) {
	type results struct {
		Answer string `jsonschema:"Answer"`
	}
	type outputs struct {
		Answer string
	}
	const maxIterations = 3
	agent := maxIterationsAgent(maxIterations)
	agent.Outputs = LLMOutputs[results]()
	agent.AllowPartialResults = true
	replies := append(maxIterationsReplies(0, maxIterations),
		// Attempt 1: replies with plain text instead of calling set-results.
		&backend.Part{Text: "Found half of the answer."},
		// Attempt 2: calls set-results.
		&backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   "id_out",
				Name: llmSetResultsTool,
				Args: map[string]any{"Answer": "Found half of the answer."},
			},
		},
	)
	testFlow[struct{}, outputs](t, nil,
		map[string]any{"Answer": "Found half of the answer."},
		agent,
		replies,
		nil,
	)
}

// TestTryAnswerNow checks how the wrap-up order is injected into the history.
func TestTryAnswerNow(t *testing.T) {
	toolResponses := &backend.Message{
		Role: backend.RoleUser,
		Parts: []backend.Part{{
			FunctionResponse: &backend.FunctionResponse{ID: "id1", Name: "some-tool"},
		}},
	}
	newSession := func(agent *LLMAgent) *agentSession {
		return &agentSession{
			LLMAgent: agent,
			req: []llmMessage{
				{content: &backend.Message{Role: backend.RoleUser, Parts: []backend.Part{{Text: "prompt"}}}},
				{content: &backend.Message{
					Role:  backend.RoleModel,
					Parts: []backend.Part{{FunctionCall: &backend.FunctionCall{ID: "id1", Name: "some-tool"}}},
				}},
				{content: toolResponses},
			},
		}
	}

	// Main agents that may not provide partial answers are not asked to wrap up.
	session := newSession(&LLMAgent{Reply: "Reply"})
	require.False(t, session.tryAnswerNow(false))
	require.False(t, session.answerNow)

	// The order is placed before the tool responses in the last message
	// (the API requires alternating roles and text parts before function responses).
	session = newSession(&LLMAgent{Reply: "Reply", AllowPartialResults: true})
	require.True(t, session.tryAnswerNow(false))
	require.True(t, session.answerNow)
	require.Equal(t, answerNowIterations, session.answerNowLeft)
	require.Len(t, session.req, 3)
	last := session.req[2].content
	require.Equal(t, backend.RoleUser, last.Role)
	require.Len(t, last.Parts, 2)
	require.Equal(t, llmReplyNow, last.Parts[0].Text)
	require.NotNil(t, last.Parts[1].FunctionResponse)
	// Repeated requests are ignored.
	require.False(t, session.tryAnswerNow(false))

	// On context overflows the order replaces the last message.
	type results struct {
		Answer string `jsonschema:"Answer"`
	}
	session = newSession(&LLMAgent{SubAgent: true, Outputs: LLMOutputs[results]()})
	require.True(t, session.tryAnswerNow(true))
	require.Len(t, session.req, 3)
	require.Equal(t, []backend.Part{{Text: llmSetResultsNow}}, session.req[2].content.Parts)
}

func TestMaxParallelToolCalls(t *testing.T) {
	type outputs struct {
		Reply string
	}
	type toolArgs struct {
		Arg int `jsonschema:"something"`
	}
	var parts []backend.Part
	for i := range maxParallelToolCalls + 1 {
		parts = append(parts, backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   fmt.Sprintf("id%d", i),
				Name: "some-tool",
				Args: map[string]any{
					"Arg": i,
				},
			},
		})
	}
	toolExecutionCount := 0
	replies := []any{
		&backend.GenerateResponse{
			Parts: parts,
		},
		func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (*backend.GenerateResponse, error) {
			require.GreaterOrEqual(t, len(req), 2)
			lastMsg := req[len(req)-1]
			require.Equal(t, backend.RoleUser, lastMsg.Role)
			require.Len(t, lastMsg.Parts, 1)
			expectedErr := fmt.Sprintf(
				"too many parallel tool calls (%d), maximum allowed is %d; "+
					"please reduce the number of tool calls per turn",
				maxParallelToolCalls+1, maxParallelToolCalls,
			)
			require.Equal(t, expectedErr, lastMsg.Parts[0].Text)
			return &backend.GenerateResponse{
				Parts: []backend.Part{{Text: "Done"}},
			}, nil
		},
	}
	testFlow[struct{}, outputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Reply: "Reply",
			Tools: []Tool{
				NewFuncTool("some-tool", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
					toolExecutionCount++
					return struct{}{}, nil
				}, "some-tool description"),
			},
		},
		replies,
		nil,
	)
	require.Equal(t, 0, toolExecutionCount, "tools should not be executed when maxParallelToolCalls is exceeded")
}

func TestLLMJudge(t *testing.T) {
	type flowOutputs struct {
		Reply         string
		JudgeStopped  bool
		JudgeReason   string
		FailedHistory []*backend.Message
	}
	type toolResults struct {
		Res int `jsonschema:"res"`
	}

	agent := &LLMAgent{
		Reply: "Reply",
		Tools: []Tool{
			NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
				return toolResults{42}, nil
			}, "ticker"),
		},
		Judge: &LLMJudge{
			Name:               "test-judge",
			Model:              "model1",
			MinIterations:      2,
			EvaluationInterval: 1,
			Instruction:        "Judge the history",
		},
	}

	expectedHistory := []*backend.Message{
		{Role: "user", Parts: []backend.Part{{Text: "Prompt"}}},
		{Role: "model", Parts: []backend.Part{{FunctionCall: &backend.FunctionCall{
			ID:   "id1",
			Name: "tick",
		}}}},
		{Role: "user", Parts: []backend.Part{{FunctionResponse: &backend.FunctionResponse{
			ID:       "id1",
			Name:     "tick",
			Response: map[string]any{"Res": 42},
		}}}},
		{Role: "model", Parts: []backend.Part{{FunctionCall: &backend.FunctionCall{
			ID:   "id2",
			Name: "tick",
		}}}},
		{Role: "user", Parts: []backend.Part{{FunctionResponse: &backend.FunctionResponse{
			ID:       "id2",
			Name:     "tick",
			Response: map[string]any{"Res": 42},
		}}}},
		{Role: "model", Parts: []backend.Part{{FunctionCall: &backend.FunctionCall{
			ID:   "id3",
			Name: "tick",
		}}}},
		{Role: "user", Parts: []backend.Part{{FunctionResponse: &backend.FunctionResponse{
			ID:       "id3",
			Name:     "tick",
			Response: map[string]any{"Res": 42},
		}}}},
	}

	testFlow[struct{}, flowOutputs](t, nil, convertToMap(flowOutputs{
		Reply:         "",
		JudgeStopped:  true,
		JudgeReason:   "stuck in tick loop",
		FailedHistory: expectedHistory,
	}),
		agent,
		[]any{
			// Iteration 0: LLM calls tick tool.
			createToolCallResponse(50, "id1", "tick"),
			// Iteration 1: LLM calls tick tool again.
			createToolCallResponse(50, "id2", "tick"),
			// Iteration 2: we use a single smart callback to handle both smarty's Turn 2 and the Judge's Turn.
			func(model string, cfg *backend.GenerateConfig, req []*backend.Message) (*backend.GenerateResponse, error) {
				if strings.Contains(cfg.SystemInstruction.Parts[0].Text, "Judge the history") {
					// This is the judge invocation!
					lastMsg := req[len(req)-1]
					hasSetResultsResponse := false
					for _, part := range lastMsg.Parts {
						if part.FunctionResponse != nil && part.FunctionResponse.Name == "set-results" {
							hasSetResultsResponse = true
							break
						}
					}
					if !hasSetResultsResponse {
						return &backend.GenerateResponse{
							Parts: []backend.Part{
								{FunctionCall: &backend.FunctionCall{
									Name: "set-results",
									Args: map[string]any{"Stop": true, "Reason": "stuck in tick loop"},
								}},
							},
						}, nil
					}
					// Turn 1 of judge: return final reply.
					return &backend.GenerateResponse{
						Parts: []backend.Part{{Text: "Done"}},
					}, nil
				}
				// This is the parent smarty agent Turn 2. Call tick tool.
				return createToolCallResponse(50, "id3", "tick"), nil
			},
		},
		nil,
	)
}

func TestLLMAdvisor(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolResults struct {
		Res int `jsonschema:"res"`
	}

	testFlow[struct{}, flowOutputs](t, nil, convertToMap(flowOutputs{
		Reply: "Advised reply",
	}),
		&LLMAgent{
			Reply: "Reply",
			Tools: Tools(NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
				return toolResults{42}, nil
			}, "ticker")),
			Advisor: &LLMAdvisor{
				Name:               "test-advisor",
				Model:              "advisor-model",
				MinIterations:      1,
				EvaluationInterval: 2,
				Instruction:        "Advise the history",
			},
		},
		[]any{
			// Iteration 0: LLM calls tick tool (advisor does not run yet since MinIterations=1).
			createToolCallResponse(50, "id1", "tick"),
			// Iteration 1: LLM calls tick tool, then advisor runs and hits BlockedError (ignored).
			createToolCallResponse(50, "id2", "tick"),
			&backend.BlockedError{Err: errors.New("request blocked: SAFETY")},
			// Iteration 2: LLM calls tick tool (advisor skipped since EvaluationInterval=2).
			createToolCallResponse(50, "id3", "tick"),
			// Iteration 3: LLM calls tick tool, then advisor runs and gives advice.
			createToolCallResponse(50, "id4", "tick"),
			&backend.Part{FunctionCall: &backend.FunctionCall{
				Name: "set-results",
				Args: map[string]any{
					"Advice": "Stop calling tick and answer now",
				},
			}},
			// Iteration 4: Main agent receives <supervisor_advice> and returns final reply.
			&backend.Part{Text: "Advised reply"},
		},
		nil,
	)
}

func TestDisarmTags(t *testing.T) {
	input := "text with <execution_history> and </execution_history> " +
		"and <thought> and </thought> and <system_instructions> and </system_instructions> " +
		"and <supervisor_advice> and </supervisor_advice> " +
		"and </EXECUTION_HISTORY> and </ execution_history > and < thought\t> " +
		"and <system_instructions priority=\"high\"> and <thought/> " +
		"and unrelated <thoughtful> <stdio.h> <div> a < b"
	got := disarmTags(input)
	want := "text with &lt;execution_history&gt; and &lt;/execution_history&gt; " +
		"and &lt;thought&gt; and &lt;/thought&gt; and &lt;system_instructions&gt; and &lt;/system_instructions&gt; " +
		"and &lt;supervisor_advice&gt; and &lt;/supervisor_advice&gt; " +
		"and &lt;/EXECUTION_HISTORY&gt; and &lt;/execution_history &gt; and &lt;thought\t&gt; " +
		"and &lt;system_instructions priority=\"high\"&gt; and &lt;thought/&gt; " +
		"and unrelated <thoughtful> <stdio.h> <div> a < b"
	require.Equal(t, want, got)
	require.Equal(t, "plain text", disarmTags("plain text"))
}
