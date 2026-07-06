// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/backend"
)

type HistorySummarizerOutputs struct {
	FailedHistorySummary string `jsonschema:"Concise summary of the failed generator attempt and its loop/mistakes."`
}

var HistorySummarizerAgent = &aflow.LLMAgent{
	Name:     "generator-history-summarizer",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs:  aflow.ValidatedLLMOutputs[HistorySummarizerOutputs, struct{}](nil),
	Instruction: "You are an expert agent analyst. Your task is to analyze the conversation history " +
		"of a failed seed generator agent that was stopped by its judge.\n" +
		"Summarize what strategy it was trying, which tools it called, and why it got stuck " +
		"(e.g., oscillating between error X and Y, repeating the same tool call with same arguments, etc.).\n" +
		"Keep the summary concise and focused on high-level strategy and pitfalls.",
	Prompt: `Failed Agent Name: seed-generator
Failed Conversation History:
{{.FormattedFailedHistoryText}}`,
}

type FormatFailedHistoryArgs struct {
}

type FormatFailedHistoryResult struct {
	FormattedFailedHistoryText string
}

var ActionFormatFailedHistory = aflow.NewFuncAction("seedgen-format-failed-history",
	func(ctx *aflow.Context, args FormatFailedHistoryArgs) (FormatFailedHistoryResult, error) {
		val := ctx.StateMap()["seed-generator_FailedHistory"]
		history, ok := val.([]*backend.Message)
		if !ok {
			return FormatFailedHistoryResult{},
				fmt.Errorf("failed history 'seed-generator_FailedHistory' not found in state context")
		}
		var sb strings.Builder
		for _, msg := range history {
			role := msg.Role
			sb.WriteString(fmt.Sprintf("[%s]:\n", role))
			for _, part := range msg.Parts {
				if part.FunctionCall != nil {
					sb.WriteString(fmt.Sprintf("  Called tool %s with args: %+v\n",
						part.FunctionCall.Name, part.FunctionCall.Args))
				} else if part.FunctionResponse != nil {
					sb.WriteString(fmt.Sprintf("  Tool %s returned: %+v\n",
						part.FunctionResponse.Name, part.FunctionResponse.Response))
				} else if part.Text != "" {
					sb.WriteString(part.Text)
					sb.WriteString("\n")
				}
			}
			sb.WriteString("\n")
		}
		return FormatFailedHistoryResult{
			FormattedFailedHistoryText: sb.String(),
		}, nil
	})
