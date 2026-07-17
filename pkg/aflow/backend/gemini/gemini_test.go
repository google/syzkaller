// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gemini

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"google.golang.org/genai"
)

func TestProviderResolveModels(t *testing.T) {
	tests := []struct {
		name          string
		modelOverride string
		category      backend.ModelCategory
		want          []string
	}{
		{
			name:     "resolves good balanced model pool",
			category: backend.GoodBalancedModel,
			want:     []string{"gemini-3.5-flash", "gemini-3-flash-preview"},
		},
		{
			name:     "resolves best expensive model pool",
			category: backend.BestExpensiveModel,
			want:     []string{"gemini-3.1-pro-preview"},
		},
		{
			name:     "returns nil for unrecognized category",
			category: "custom-model",
			want:     nil,
		},
		{
			name:          "respects provider level override",
			modelOverride: "override-model",
			category:      backend.GoodBalancedModel,
			want:          []string{"override-model"},
		},
		{
			name:          "respects provider level override even for unrecognized model type",
			modelOverride: "override-model",
			category:      "custom-model",
			want:          []string{"override-model"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Provider{modelOverride: tc.modelOverride}
			got := provider.ResolveModels(tc.category)
			if !slices.Equal(got, tc.want) {
				t.Errorf("provider.ResolveModels(%v) = %v, want %v", tc.category, got, tc.want)
			}
		})
	}
}

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
	tests := []Test{
		{
			inputErr:  tpmError1,
			outputErr: &backend.RetryError{Delay: 25 * time.Second, Err: tpmError1},
		},
		{
			inputErr: genai.APIError{
				Code:    429,
				Message: `Resource has been exhausted (e.g. check quota).`,
			},
			outputErr: &backend.RetryError{
				Delay: time.Minute,
				Err: genai.APIError{
					Code:    429,
					Message: `Resource has been exhausted (e.g. check quota).`,
				},
			},
		},
		{
			inputErr: genai.APIError{
				Code: 400,
				// nolint:lll
				Message: `The input token count exceeds the maximum limit for this model. The input token count is 1000001, but the maximum limit is 1000000.`,
			},
			outputErr: &backend.InputTokenOverflowError{
				Err: genai.APIError{
					Code: 400,
					// nolint:lll
					Message: `The input token count exceeds the maximum limit for this model. The input token count is 1000001, but the maximum limit is 1000000.`,
				},
			},
		},
		{
			resp: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						FinishReason: genai.FinishReasonMaxTokens,
					},
				},
			},
			outputErr: &backend.OutputTokenOverflowError{
				Err: errors.New("MAX_TOKENS"),
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var err error
			if test.inputErr != nil {
				err = parseLLMError(test.inputErr, "smarty")
			} else if test.resp != nil {
				err = parseLLMResp(test.resp)
			}
			if err == nil || test.outputErr == nil {
				if err != test.outputErr {
					t.Errorf("got %v, want %v", err, test.outputErr)
				}
			} else if err.Error() != test.outputErr.Error() {
				t.Errorf("got %v, want %v", err, test.outputErr)
			}
		})
	}
}

func TestParseLLMErrorBackoff(t *testing.T) {
	// Let's verify that RetryErrors are correctly parsed to backoff formats from code.
	err0 := genai.APIError{Code: 503}
	err := parseLLMError(err0, "model")
	var rErr *backend.RetryError
	if !errors.As(err, &rErr) || rErr.Delay != time.Second || !rErr.IsExponential {
		t.Errorf("expected RetryError with 1s exponential delay, got %v", err)
	}
}
