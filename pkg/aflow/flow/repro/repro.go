// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/prog"
)

type ReproInputs struct {
	BugTitle     string
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

func init() {
	aflow.Register[ReproInputs, ai.ReproOutputs](
		ai.WorkflowRepro,
		"reproduce a kernel crash and generate a syzlang program",
		&aflow.Flow{
			Root: aflow.Pipeline(
				aflow.Provide(struct {
					SyzkallerCommit  string
					DescriptionFiles []string
				}{
					prog.GitRevisionBase,
					syzlang.DescriptionFiles(),
				}),
				kernel.Checkout,
				kernel.Build,
				&aflow.LLMAgent{
					Name:  "crash-repro-finder",
					Model: aflow.BestExpensiveModel,
					Reply: "ReproSyz",
					Outputs: aflow.LLMOutputs[struct {
						ReproOpts string `jsonschema:"The repro configuration options."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reproInstruction,
					Prompt:      reproPrompt,
				},
			),
		},
	)
}

const reproInstruction = `
You are an expert in linux kernel fuzzing. Your goal is to write a syzkaller program to trigger a specific bug.
Print only the syz program that could be executed directly, without backticks.

{{if .KernelObj}}{{end}}
`

const reproPrompt = `
Bug Title: {{.BugTitle}}

Original Crash Report:
{{.CrashReport}}

The list of existing description files:
{{range $file := .DescriptionFiles}}{{$file}}
{{end}}
`
