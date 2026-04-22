// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
)

type ReproCInputs struct {
	BugDescription  string
	SyzkallerCommit string // Forwarded to output for debugging and provenance.

	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

func init() {
	aflow.Register[ReproCInputs, ai.ReproCOutputs](
		ai.WorkflowReproC,
		"reproduce a kernel crash and generate a C reproducer",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				&aflow.LLMAgent{
					Name:        "crash-reproc-finder",
					Model:       aflow.BestExpensiveModel,
					Reply:       "ReproC",
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reprocInstruction,
					Prompt:      reprocPrompt,
				},
			),
		},
	)
}

const reprocInstruction = `
You are an expert in linux kernel fuzzing. Your goal is to write a C program to trigger a specific bug.
Print only the C program that could be executed directly, without backticks.

{{if .KernelObj}}{{end}}
`

const reprocPrompt = `
Bug Description:
{{.BugDescription}}
`
