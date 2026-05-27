// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type moderationInputs struct {
	TargetOS     string
	TargetArch   string
	BugTitle     string
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

// nolint:dupl
func init() {
	aflow.Register[moderationInputs, ai.ModerationOutputs](
		ai.WorkflowModeration,
		"assess if a bug report is consistent and actionable or not",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:  "expert",
					Model: aflow.GoodBalancedModel,
					Reply: "ExplanationRaw",
					Outputs: aflow.LLMOutputs[struct {
						Actionable bool `jsonschema:"If the report is actionable or not."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: common.Prompt(prompts, "prompts/moderation_instruction.md"),
					Prompt:      moderationPrompt,
					Tools:       common.CodeAccessTools,
				},
				formatExplanation,
			),
		},
	)
}

const moderationPrompt = `
The bug report is:

{{.CrashReport}}
`
