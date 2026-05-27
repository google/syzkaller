// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"encoding/json"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/prog"
)

type ReproInputs struct {
	TargetOS     string
	TargetArch   string
	BugTitle     string
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	Image        string
	Type         string
	VM           json.RawMessage
	Syzkaller    string
	StraceBin    string
}

func init() {
	aflow.Register[ReproInputs, ai.ReproOutputs](
		ai.WorkflowRepro,
		"reproduce a kernel crash and generate a syzlang program",
		&aflow.Flow{
			Consts: map[string]any{
				"SyzkallerCommit":              prog.GitRevisionBase,
				"DescriptionFiles":             syzlang.DescriptionFiles(),
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"ReproC":                       "", // is needed by crash.Reproduce
				"NeedStrace":                   false,
			},
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:  "crash-repro-finder",
					Model: aflow.BestExpensiveModel,
					Outputs: aflow.LLMOutputs[struct {
						ReproOpts         string `jsonschema:"The repro configuration options."`
						CandidateReproSyz string `jsonschema:"Valid syzkaller reproducer program without triple backticks."`
					}](),
					Tools: aflow.Tools(
						common.CodeAccessTools,
						syzlang.ReadDescription,
						syzlang.Reproduce,
						syzlang.Coverage,
					),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reproInstruction,
					Prompt:      reproPrompt,
				},
				actionsyzlang.Format,
				crash.Reproduce,
				aflow.NewFuncAction("compare", func(ctx *aflow.Context,
					args struct {
						BugTitle           string
						ReproducedBugTitle string
						// This is an unused output of crash.Reproduce.
						// TODO: figure out how to handle such outputs better.
						ReproducedFaultInjection string
					}) (struct{ Reproduced bool }, error) {
					return struct{ Reproduced bool }{args.BugTitle == args.ReproducedBugTitle}, nil
				}),
			),
		},
	)
}

const reproInstruction = `
You are an expert in the Linux kernel fuzzing. Your goal is to write a syzkaller program to trigger a specific bug.

Document about syzkaller program syntax:
===
{{.DocProgramSyntax}}
===

Document about syzlang system call descriptions syntax:
===
{{.DocSyscallDescriptionsSyntax}}
===
` + common.InstructionDontMakeAssumptionsAboutSourceCode

const reproPrompt = `
Bug title: {{.BugTitle}}

The bug report to reproduce:
{{.CrashReport}}

The list of existing description files:
{{range $file := .DescriptionFiles}}{{$file}}
{{end}}
`
