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
	tpsError := genai.APIError{
		Code: 429,
		// nolint:lll
		Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. * Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_paid_tier_input_token_count, limit: 1000000, model: gemini-3-flash Please retry in 24.180878813s.`,
	}
	rpmError := genai.APIError{
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
			inputErr:  tpsError,
			outputErr: &retryError{25 * time.Second, tpsError},
		},
		{
			resp:      nil,
			inputErr:  rpmError,
			outputErr: &modelQuotaError{"smarty"},
		},
		{
			resp:      nil,
			inputErr:  tokenError,
			outputErr: &tokenOverflowError{tokenError},
		},
		{
			resp:      nil,
			inputErr:  iseError,
			outputErr: &retryError{time.Second, iseError},
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
	err0 := genai.APIError{Code: http.StatusServiceUnavailable}
	for try := 0; try < maxLLMRetryIters; try++ {
		wantDelay := min(maxLLMBackoff, time.Duration(try+1)*time.Second)
		err := parseLLMError(nil, err0, "model", try)
		require.Equal(t, err, &retryError{wantDelay, err0})
	}
	err := parseLLMError(nil, err0, "model", maxLLMRetryIters)
	require.Equal(t, err, err0)
}

func TestSummaryWindow(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolResults struct {
		ResFoo int `jsonschema:"foo"`
	}
	requestSeq := 0
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{"Reply": "Done"},
		&LLMAgent{
			Name:          "summary_agent",
			Model:         "model",
			Reply:         "Reply",
			SummaryWindow: 3,
			TaskType:      FormalReasoningTask,
			Instruction:   "Instructions",
			Prompt:        "Initial Prompt",
			Tools: []Tool{
				NewFuncTool("tick", func(ctx *Context, state struct{}, args struct{}) (toolResults, error) {
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
	)
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
			Name:        "smarty",
			Model:       "model",
			Reply:       "Reply",
			Outputs:     LLMOutputs[flowResults](),
			TaskType:    FormalReasoningTask,
			Instruction: "Instructions",
			Prompt:      "Initial Prompt",
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
	)
}
