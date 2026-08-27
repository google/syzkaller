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
	Model:    aflow.CoreModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs:  aflow.LLMOutputs[HistorySummarizerOutputs](),
	Instruction: `You are an expert agent analyst. Your task is to analyze the conversation history of a
failed seed generator agent that was stopped by its judge or hit an execution error.

Produce a structured, concise, and highly actionable FailedHistorySummary to guide the next
generator attempt.

You MUST structure your FailedHistorySummary into the following four markdown sections:
1. ## FAILED STRATEGY & SYSCALL PATHS
2. ## REPEATED ERRORS & STUCK LOOPS
3. ## DISCARDED TEST SEEDS & SYZLANG CONSTRUCTS
4. ## RECOMMENDED ALTERNATIVE DIRECTIONS & NEGATIVE CONSTRAINTS`,
	Prompt: `Failed Agent Name: seed-generator
Failed Conversation History:
{{.FormattedFailedHistoryText}}`,
}

type FormatFailedHistoryArgs struct {
	FailedHistory []*backend.Message
}

type FormatFailedHistoryResult struct {
	FormattedFailedHistoryText string
}

var ActionFormatFailedHistory = aflow.NewFuncAction("seedgen-format-failed-history",
	func(ctx *aflow.Context, args FormatFailedHistoryArgs) (FormatFailedHistoryResult, error) {
		if len(args.FailedHistory) == 0 {
			return FormatFailedHistoryResult{}, fmt.Errorf("failed history not found in state context")
		}
		var sb strings.Builder
		for _, msg := range args.FailedHistory {
			fmt.Fprintf(&sb, "[%s]:\n", msg.Role)
			for _, part := range msg.Parts {
				switch {
				case part.FunctionCall != nil:
					fmt.Fprintf(&sb, "  Called tool %s with args: %+v\n",
						part.FunctionCall.Name, part.FunctionCall.Args)
				case part.FunctionResponse != nil:
					fmt.Fprintf(&sb, "  Tool %s returned: %+v\n",
						part.FunctionResponse.Name, part.FunctionResponse.Response)
				case part.Text != "":
					fmt.Fprintln(&sb, part.Text)
				}
			}
			sb.WriteString("\n")
		}
		return FormatFailedHistoryResult{
			FormattedFailedHistoryText: sb.String(),
		}, nil
	})
