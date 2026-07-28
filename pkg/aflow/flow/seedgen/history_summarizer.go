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
	FailedHistorySummary string `jsonschema:"Structured failure analysis summary."`
}

var HistorySummarizerAgent = &aflow.LLMAgent{
	Name:     "generator-history-summarizer",
	Model:    aflow.TemporaryFlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs:  aflow.ValidatedLLMOutputs[HistorySummarizerOutputs, struct{}](nil),
	Instruction: "You are an expert agent analyst. Your task is to analyze the conversation history of a " +
		"failed seed generator agent that was stopped by its judge or hit an execution error.\n\n" +
		"Produce a structured, concise, and highly actionable FailedHistorySummary to guide the next " +
		"generator attempt.\n\n" +
		"You MUST structure your FailedHistorySummary into the following four markdown sections:\n" +
		"1. ## FAILED STRATEGY & SYSCALL PATHS\n" +
		"2. ## REPEATED ERRORS & STUCK LOOPS\n" +
		"3. ## DISCARDED BASE SEEDS & SYZLANG CONSTRUCTS\n" +
		"4. ## RECOMMENDED ALTERNATIVE DIRECTIONS & NEGATIVE CONSTRAINTS",
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
