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

func TestLLMJudgeFormatHistory(t *testing.T) {
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
					{
						Thought: true,
						Text:    "   \n",
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
					{
						FunctionResponse: &backend.FunctionResponse{
							Name: "empty-tool",
						},
					},
				},
			},
			tokenCount: 50000,
		},
	}

	formatted := formatJudgeHistory(rawHistory)
	want := `<execution_history>
[user]:
initial prompt

[model]:
  Called tool execute-seed with args: {}
<thought>
analyzing seed
</thought>

[user]:
  Tool execute-seed returned: {"output":"seed run success"}
  Tool empty-tool returned: {}

</execution_history>
`
	require.Equal(t, want, formatted)
}

func TestDisarmTags(t *testing.T) {
	input := "text with <execution_history> and </execution_history> " +
		"and <thought> and </thought> and <system_instructions> and </system_instructions> " +
		"and </EXECUTION_HISTORY> and </ execution_history > and < thought\t> " +
		"and <system_instructions priority=\"high\"> and <thought/> " +
		"and unrelated <thoughtful> <stdio.h> <div> a < b"
	got := disarmTags(input)
	want := "text with &lt;execution_history&gt; and &lt;/execution_history&gt; " +
		"and &lt;thought&gt; and &lt;/thought&gt; and &lt;system_instructions&gt; and &lt;/system_instructions&gt; " +
		"and &lt;/EXECUTION_HISTORY&gt; and &lt;/execution_history &gt; and &lt;thought\t&gt; " +
		"and &lt;system_instructions priority=\"high\"&gt; and &lt;thought/&gt; " +
		"and unrelated <thoughtful> <stdio.h> <div> a < b"
	require.Equal(t, want, got)
	require.Equal(t, "plain text", disarmTags("plain text"))
}
