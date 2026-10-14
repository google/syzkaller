// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type kcsanInputs struct {
	TargetOS     string
	TargetArch   string
	TargetVMArch string `json:",omitempty"`
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

const kcsanPrompt = `
The data race report is:

{{.CrashReport}}
`

type kcsanOutputs struct {
	Benign              bool   `jsonschema:"If the data race is benign or not."`
	FailureDetectableBy string `json:",omitempty" jsonschema:"Downstream detector: kasan|kmsan|any|user|none."`
}

var validKCSANFailureDetectableBy = []string{
	ai.KCSANFailureDetectableByKASAN,
	ai.KCSANFailureDetectableByKMSAN,
	ai.KCSANFailureDetectableByAny,
	ai.KCSANFailureDetectableByUser,
	ai.KCSANFailureDetectableByNone,
}

func validateKCSANOutputs(ctx *aflow.Context, state struct{}, args kcsanOutputs) (kcsanOutputs, error) {
	if args.Benign {
		args.FailureDetectableBy = ""
		return args, nil
	}
	if !slices.Contains(validKCSANFailureDetectableBy, args.FailureDetectableBy) {
		return args, aflow.BadCallError(
			"FailureDetectableBy must be one of %v when Benign is false, got %q",
			validKCSANFailureDetectableBy, args.FailureDetectableBy)
	}
	return args, nil
}

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
					Name:        "expert",
					Model:       aflow.CoreModel,
					Reply:       "ExplanationRaw",
					Outputs:     aflow.ValidatedLLMOutputs(validateKCSANOutputs),
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
