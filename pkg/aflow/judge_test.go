// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/require"
)

func TestLLMJudgeVerify(t *testing.T) {
	tests := []struct {
		name       string
		judge      *LLMJudge
		wantErrMsg string
	}{
		{
			name: "valid configuration",
			judge: &LLMJudge{
				Name:               "valid-judge",
				Model:              "model1",
				EvaluationInterval: 1,
				MinIterations:      1,
				Instruction:        "Analyze history",
			},
			wantErrMsg: "",
		},
		{
			name: "zero EvaluationInterval",
			judge: &LLMJudge{
				Name:               "zero-interval-judge",
				Model:              "model1",
				EvaluationInterval: 0,
				Instruction:        "Analyze history",
			},
			wantErrMsg: "EvaluationInterval must be greater than 0",
		},
		{
			name: "negative EvaluationInterval",
			judge: &LLMJudge{
				Name:               "neg-interval-judge",
				Model:              "model1",
				EvaluationInterval: -1,
				Instruction:        "Analyze history",
			},
			wantErrMsg: "EvaluationInterval must be greater than 0",
		},
		{
			name: "zero MinIterations",
			judge: &LLMJudge{
				Name:               "zero-min-iters-judge",
				Model:              "model1",
				EvaluationInterval: 1,
				MinIterations:      0,
				Instruction:        "Analyze history",
			},
			wantErrMsg: "MinIterations must be greater than 0",
		},
		{
			name: "negative MinIterations",
			judge: &LLMJudge{
				Name:               "neg-min-iters-judge",
				Model:              "model1",
				EvaluationInterval: 1,
				MinIterations:      -1,
				Instruction:        "Analyze history",
			},
			wantErrMsg: "MinIterations must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.judge.verify()
			if tt.wantErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrMsg)
			}
		})
	}
}

func TestLLMJudgeInitChatHistory(t *testing.T) {
	judge := &LLMJudge{
		Name:               "test-judge",
		Model:              "model1",
		EvaluationInterval: 1,
		MinIterations:      1,
		Instruction:        "Judge the history",
	}
	require.NoError(t, judge.verify())

	rawHistory := []llmMessage{
		{
			content: &backend.Message{
				Role:  backend.RoleUser,
				Parts: []backend.Part{{Text: "initial prompt"}},
			},
			tokenCount: 1000,
		},
		{
			content: &backend.Message{
				Role: backend.RoleModel,
				Parts: []backend.Part{
					{
						FunctionCall: &backend.FunctionCall{Name: "execute-seed"},
					},
					{
						Thought: true,
						Text:    "analyzing seed",
					},
				},
			},
			tokenCount: 500,
		},
		{
			content: &backend.Message{
				Role: backend.RoleUser,
				Parts: []backend.Part{
					{
						FunctionResponse: &backend.FunctionResponse{
							Name:     "execute-seed",
							Response: map[string]any{"output": "seed run success"},
						},
					},
				},
			},
			tokenCount: 50000,
		},
	}

	ctx := &Context{
		state: map[string]any{
			judgeStateHistory: rawHistory,
		},
	}
	gotHistory, err := judge.agent.InitChatHistoryFunc(ctx)
	require.NoError(t, err)
	require.Equal(t, rawHistory, gotHistory)
}
