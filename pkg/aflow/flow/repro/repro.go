// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type ReproInputs struct {
	BugTitle        string
	CrashReport     string
	KernelConfig    string
	KernelRepo      string
	KernelCommit    string
	Syzkaller       string
	SyzkallerCommit string
	Image           string
	Type            string
	VM              json.RawMessage
}

func init() {
	aflow.Register[ReproInputs, ai.ReproOutputs](
		ai.WorkflowRepro,
		"reproduce a kernel crash and generate a syzlang program",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				&aflow.DoWhile{
					Do: aflow.Pipeline(
						&aflow.LLMAgent{
							Name:        "crash-reproducer",
							Model:       aflow.BestExpensiveModel,
							Reply:       "RawSyzlang",
							TaskType:    aflow.FormalReasoningTask,
							Instruction: reproInstruction,
							Prompt:      reproPrompt,
							Tools:       syzlang.Tools,
						},
						crash.ExtractSyzCode,
						crash.SyzCompilerCheck,
						// If compiler succeeded, evaluate Reproduce and Compare outputs
						// In order to not fail early if reproduce failed or compile failed, we use an aggregator
						aflow.NewFuncAction("evaluate-iteration", func(ctx *aflow.Context, args struct {
							CompilerSuccess     bool
							CompilerErrors      string
							ReproduceErrors     string
							CompareErrors       string
							ProducedCrashReport string
						}) (struct{ IterationErrors string }, error) {
							if !args.CompilerSuccess {
								return struct{ IterationErrors string }{IterationErrors: args.CompilerErrors}, nil
							}
							if args.ReproduceErrors != "" {
								return struct{ IterationErrors string }{IterationErrors: args.ReproduceErrors}, nil
							}
							if args.CompareErrors != "" {
								return struct{ IterationErrors string }{IterationErrors: args.CompareErrors}, nil
							}
							return struct{ IterationErrors string }{}, nil
						}),
						crash.ReproduceSyzlang,
						crash.CompareCrashSignature,
					),
					While:         "IterationErrors",
					MaxIterations: 10,
				},
				aflow.NewFuncAction("emit-result", func(ctx *aflow.Context, args struct {
					CandidateSyzlang string
					Matches          bool
				}) (ai.ReproOutputs, error) {
					return ai.ReproOutputs{
						Syzlang: args.CandidateSyzlang,
						Success: args.Matches,
					}, nil
				}),
			),
		},
	)
}

const reproInstruction = `
You are an expert in linux kernel fuzzing. Your goal is to write a syzkaller program to trigger
a specific bug. Use syzlang syntax strictly.

First, search for the relevant syzlang definitions using the syzlang-search tool.
Then, write a candidate .syz test program. Use the syz-compiler-check tool to validate your syntax.
Once compilation passes, use the crash-reproducer tool to run it in the VM.
After that, use compare-crash-signature to verify if the reproduced crash matches the target crash title.

If previous attempts failed, pay attention to the errors and fix them.
`

const reproPrompt = `
Original Crash Report:
{{.CrashReport}}

{{if .IterationErrors}}
Previous Attempt Errors:
{{.IterationErrors}}
{{end}}
`
