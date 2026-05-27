// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type kcsanInputs struct {
	TargetOS     string
	TargetArch   string
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

const kcsanPrompt = `
The data race report is:

{{.CrashReport}}
`

// nolint:dupl
func init() {
	aflow.Register[kcsanInputs, ai.AssessmentKCSANOutputs](
		ai.WorkflowAssessmentKCSAN,
		"assess if a KCSAN report is about a benign race that only needs annotations or not",
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
						Benign bool `jsonschema:"If the data race is benign or not."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: common.Prompt(prompts, "prompts/kcsan_instruction.md"),
					Prompt:      kcsanPrompt,
					Tools:       common.CodeAccessTools,
				},
				formatExplanation,
			),
		},
	)
}
