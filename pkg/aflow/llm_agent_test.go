// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genai"
)

func TestParseLLMError(t *testing.T) {
	type Test struct {
		resp      *genai.GenerateContentResponse
		inputErr  error
		outputErr error
	}
	tpmError1 := genai.APIError{
		Code: 429,
		// nolint:lll
		Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. * Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_paid_tier_input_token_count, limit: 1000000, model: gemini-3-flash Please retry in 24.180878813s.`,
	}
	tpmError2 := genai.APIError{
		Code: 429,
		// nolint:lll
		Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit.`,
	}
	vertexError1 := genai.APIError{
		Code: 429,
		// nolint:lll
		Message: `Resource exhausted. Please try again later. Please refer to https://cloud.google.com/vertex-ai/generative-ai/docs/error-code-429 for more details.`,
	}
	vertexError2 := genai.APIError{
		Code:    429,
		Message: `Resource has been exhausted (e.g. check quota).`,
	}
	rpdError := genai.APIError{
		Code: 429,
		// nolint:lll
		Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. * Quota exceeded for metric: generativelanguage.googleapis.com/generate_requests_per_model_per_day, limit: 0`,
	}
	tokenError := genai.APIError{
		Code:    400,
		Message: `The input token count exceeds the maximum number of tokens allowed 1048576.`,
	}
	iseError := genai.APIError{
		Code:    500,
		Message: `Internal error encountered.`,
	}
	badGatewayError := genai.APIError{
		Code:    502,
		Message: `Bad Gateway`,
	}
	gatewayError1 := genai.APIError{
		Code:    504,
		Message: `Cancelled while waiting for stream data; Failed to close the streaming context.`,
	}
	gatewayError2 := genai.APIError{
		Code:    504,
		Message: `Deadline expired before operation could complete.`,
	}
	cancelledError := genai.APIError{
		Code:    499,
		Message: `The operation was cancelled.`,
	}
	normalResp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{{
			Content: genai.NewContentFromText("repy", genai.RoleModel),
		}},
	}
	tests := []Test{
		{
			resp:     normalResp,
			inputErr: nil,
		},
		{
			resp:      nil,
			inputErr:  fmt.Errorf("non API error"),
			outputErr: fmt.Errorf("non API error"),
		},
		{
			resp:      nil,
			inputErr:  tpmError1,
			outputErr: &retryError{25 * time.Second, tpmError1},
		},
		{
			resp:      nil,
			inputErr:  tpmError2,
			outputErr: &retryError{time.Minute, tpmError2},
		},
		{
			resp:      nil,
			inputErr:  vertexError1,
			outputErr: &retryError{time.Minute, vertexError1},
		},
		{
			resp:      nil,
			inputErr:  vertexError2,
			outputErr: &retryError{time.Minute, vertexError2},
		},
		{
			resp:      nil,
			inputErr:  rpdError,
			outputErr: &modelQuotaError{"smarty"},
		},
		{
			resp:      nil,
			inputErr:  tokenError,
			outputErr: &inputTokenOverflowError{tokenError},
		},
		{
			resp:      nil,
			inputErr:  iseError,
			outputErr: &retryError{time.Second, iseError},
		},
		{
			resp:      nil,
			inputErr:  badGatewayError,
			outputErr: &retryError{time.Second, badGatewayError},
		},
		{
			resp:      nil,
			inputErr:  gatewayError1,
			outputErr: &retryError{time.Second, gatewayError1},
		},
		{
			resp:      nil,
			inputErr:  gatewayError2,
			outputErr: &retryError{time.Second, gatewayError2},
		},
		{
			resp:      nil,
			inputErr:  cancelledError,
			outputErr: &retryError{time.Second, cancelledError},
		},
		{
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						FinishReason: genai.FinishReasonMalformedFunctionCall,
					},
				},
			},
			outputErr: &retryError{0, errors.New(string(genai.FinishReasonMalformedFunctionCall))},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			err := parseLLMError(test.resp, test.inputErr, "smarty", 0)
			assert.Equal(t, test.outputErr, err)
		})
	}
}

func TestParseLLMErrorBackoff(t *testing.T) {
	var totalBackoff time.Duration
	err0 := genai.APIError{Code: http.StatusServiceUnavailable}
	for try := range maxLLMRetryIters {
		wantBackoff := llmBackoffDuration(try)
		t.Logf("iter %v: %v", try, wantBackoff)
		err := parseLLMError(nil, err0, "model", try)
		require.Equal(t, err, &retryError{wantBackoff, err0})
		totalBackoff += wantBackoff
	}
	err := parseLLMError(nil, err0, "model", maxLLMRetryIters)
	require.Equal(t, err, err0)
	t.Logf("total backoff: %v", totalBackoff)
}

func TestSummaryWindow(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolResults struct {
		ResFoo int `jsonschema:"foo"`
	}
	type toolArgs struct {
		Seq int `jsonschema:"seq"`
	}
	requestSeq := 0
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Reply:         "Reply",
			summaryWindow: 3,
			Tools: []Tool{
				NewFuncTool("tick", func(ctx *Context, state struct{}, args toolArgs) (toolResults, error) {
					return toolResults{123}, nil
				}, "logic ticker"),
			},
		},
		[]any{
			func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
				*genai.GenerateContentResponse, error) {
				requestSeq++
				reply := []*genai.Part{{
					FunctionCall: &genai.FunctionCall{
						ID:   fmt.Sprintf("id%v", requestSeq),
						Name: "tick",
						Args: map[string]any{"Seq": float64(requestSeq)},
					}}}
				lastReq := req[len(req)-1]
				lastPart := lastReq.Parts[len(lastReq.Parts)-1]
				if lastPart.Text == slidingWindowInstruction {
					reply = append(reply, genai.NewPartFromText(fmt.Sprintf("summary %v", requestSeq)))
				} else if requestSeq > 6 {
					reply = []*genai.Part{genai.NewPartFromText("Done")}
				}
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{
						Content: &genai.Content{
							Parts: reply,
							Role:  genai.RoleModel,
						}}}}, nil
			},
		},
		nil,
	)
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
			&genai.GenerateContentResponse{
				UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
					PromptTokenCount:     260,
					CandidatesTokenCount: 10,
				},
				Candidates: []*genai.Candidate{{
					Content: &genai.Content{
						Parts: []*genai.Part{genai.NewPartFromText("compressed summary")},
						Role:  genai.RoleModel,
					}}}},
			// 4. The main agent resumes with the truncated history. We finish the workflow.
			func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (*genai.GenerateContentResponse, error) {
				// Assert that the history was correctly truncated!
				assert.Equal(t, 2, len(req), "History should be truncated to just Anchor and Summary")

				// Assert Anchor Message remains untouched.
				assert.Equal(t, "Prompt", req[0].Parts[0].Text)

				// Assert Summary is correctly formatted.
				assert.Equal(t, "Here is the summary of the previous execution history:\n\ncompressed summary",
					req[1].Parts[0].Text)
				return &genai.GenerateContentResponse{
					UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
						PromptTokenCount:     20, // tokens dropped after compression
						CandidatesTokenCount: 10,
					},
					Candidates: []*genai.Candidate{{
						Content: &genai.Content{
							Parts: []*genai.Part{genai.NewPartFromText("Done")},
							Role:  genai.RoleModel,
						}}}}, nil
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
			&genai.GenerateContentResponse{
				UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
					PromptTokenCount:     260,
					CandidatesTokenCount: 10,
				},
				Candidates: []*genai.Candidate{{
					Content: &genai.Content{
						Parts: []*genai.Part{genai.NewPartFromText("compressed summary")},
						Role:  genai.RoleModel,
					}}}},
			createToolCallResponse(50, "id4", "tick"),
			genai.NewPartFromText("Done"),
		},
		nil,
	)
	require.Equal(t, 4, toolExecutionCount, "toolHistory was not reset on compression!")
}

func createToolCallResponse(tokens int32, id, name string) *genai.GenerateContentResponse {
	return &genai.GenerateContentResponse{
		UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
			PromptTokenCount:     tokens,
			CandidatesTokenCount: 10,
		},
		Candidates: []*genai.Candidate{{
			Content: &genai.Content{
				Parts: []*genai.Part{
					{FunctionCall: &genai.FunctionCall{ID: id, Name: name}},
				},
				Role: genai.RoleModel,
			}}},
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
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "tool"}},
			genai.NewPartFromText("Done"),
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
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
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
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "swiss-knife", Args: map[string]any{"Optional": nil}}},
			genai.NewPartFromText("Result"),
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
			genai.NewPartFromText("Ignored"),
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
		`flow test: action smarty: summaryWindow and compressTokens are mutually exclusive`,
		&Flow{
			Root: &LLMAgent{
				Name:           "smarty",
				Model:          "model",
				Reply:          "Result",
				TaskType:       FormalReasoningTask,
				Instruction:    "Instruction",
				Prompt:         "Prompt",
				summaryWindow:  3,
				compressTokens: 100,
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
	overflowResp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{{
			FinishReason: genai.FinishReasonMaxTokens,
		}},
	}
	testFlow[struct{}, flowResults](t, nil, string(genai.FinishReasonMaxTokens),
		&LLMAgent{
			Reply: "Result",
			Outputs: LLMOutputs[struct {
				Output int `jsonschema:"Some output."`
			}](),
		},
		[]any{
			// First return few overflow errors. The framework should reduce amount of thinking.
			overflowResp,
			overflowResp,
			overflowResp,
			// But in the end the invocation succeeds.
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "set-results", Args: map[string]any{"Output": 42}}},
			// The framework should reset the thinking level back to HIGH for the new request.
			// The request fails even with minimal level of thinking.
			overflowResp,
			overflowResp,
			overflowResp,
			overflowResp,
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
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 42}}},
			// Second try returns a result that is modified by the validation function.
			&genai.Part{FunctionCall: &genai.FunctionCall{Name: "set-results", Args: map[string]any{"Result": 100}}},
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
			genai.NewPartFromText("reply1"),
			genai.NewPartFromText("reply2"),
		},
		nil,
	)
}
