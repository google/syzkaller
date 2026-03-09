// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
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
					SyzkallerCommit              string
					DescriptionFiles             []string
					DocProgramSyntax             string
					DocSyscallDescriptionsSyntax string
				}{
					prog.GitRevisionBase,
					syzlang.DescriptionFiles(),
					docs.ProgramSyntax,
					docs.SyscallDescriptionsSyntax,
				}),
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:  "crash-repro-finder",
					Model: aflow.BestExpensiveModel,
					Reply: "ReproSyz",
					Outputs: aflow.LLMOutputs[struct {
						ReproOpts string `jsonschema:"The repro configuration options."`
					}](),
					Tools: aflow.Tools(
						syzlang.ReadDescription,
						syzlang.Reproduce,
						codesearcher.Tools,
						grepper.Tool,
					),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reproInstruction,
					Prompt:      reproPrompt,
				},
			),
		},
	)
}

const reproInstruction = `
You are an expert in the Linux kernel fuzzing. Your goal is to write a syzkaller program to trigger a specific bug.
In the final output provide only the syz program that triggers the bug, and could be executed directly,
without backticks.

Don't make assumptions about the kernel source code, use the provided codesearch tools
to examine the kernel code instead.

Document about syzkaller program syntax:
===
{{.DocProgramSyntax}}
===

Document about syzlang system call descriptions syntax:
===
{{.SyscallDescriptionsSyntax}}
===
`

const reproPrompt = `
Bug title: {{.BugTitle}}

The bug report to reproduce:
{{.CrashReport}}

The list of existing description files:
{{range $file := .DescriptionFiles}}{{$file}}
{{end}}
`
