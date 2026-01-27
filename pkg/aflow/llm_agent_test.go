// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
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
		retry     time.Duration
		outputErr error
	}
	// nolint:lll
	tests := []Test{
		{
			resp:     nil,
			inputErr: nil,
		},
		{
			resp:      nil,
			inputErr:  fmt.Errorf("non API error"),
			outputErr: fmt.Errorf("non API error"),
		},
		{
			resp: nil,
			inputErr: genai.APIError{
				Code:    429,
				Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. * Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_paid_tier_input_token_count, limit: 1000000, model: gemini-3-flash Please retry in 24.180878813s.`,
			},
			retry: 25 * time.Second,
		},
		{
			resp: nil,
			inputErr: genai.APIError{
				Code:    429,
				Message: `You exceeded your current quota, please check your plan and billing details. For more information on this error, head to: https://ai.google.dev/gemini-api/docs/rate-limits. To monitor your current usage, head to: https://ai.dev/rate-limit. * Quota exceeded for metric: generativelanguage.googleapis.com/generate_requests_per_model_per_day, limit: 0`,
			},
			outputErr: &modelQuotaError{"smarty"},
		},
		{
			resp: nil,
			inputErr: genai.APIError{
				Code:    400,
				Message: `The input token count exceeds the maximum number of tokens allowed 1048576.`,
			},
			outputErr: &tokenOverflowError{genai.APIError{
				Code:    400,
				Message: `The input token count exceeds the maximum number of tokens allowed 1048576.`,
			}},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var backoff time.Duration
			retry, err := parseLLMError(test.resp, test.inputErr, "smarty", 1, &backoff)
			assert.Equal(t, test.retry, retry)
			assert.Equal(t, test.outputErr, err)
		})
	}
}

func TestParseLLMErrorBackoff(t *testing.T) {
	var backoff time.Duration
	err0 := genai.APIError{Code: http.StatusServiceUnavailable}
	for try := 0; try < maxLLMRetryIters; try++ {
		retry, err := parseLLMError(nil, err0, "model", try, &backoff)
		require.Equal(t, retry, min(maxLLMBackoff, time.Duration(try+1)*time.Second))
		require.NoError(t, err)
	}
	retry, err := parseLLMError(nil, err0, "model", maxLLMRetryIters, &backoff)
	require.Equal(t, retry, time.Duration(0))
	require.Equal(t, err, err0)
}
