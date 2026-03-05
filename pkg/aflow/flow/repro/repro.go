// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	toolcrash "github.com/google/syzkaller/pkg/aflow/tool/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type ReproInputs struct {
	BugTitle     string
	CrashReport  string
	KernelConfig string
	KernelRepo   string
	KernelCommit string
	Syzkaller    string
	Image        string
	Type         string
	VM           json.RawMessage

	// We don't use them. Needed to use crash.Reproduce.
	ReproOpts string
	ReproC    string
}

func init() {
	aflow.Register[ReproInputs, ai.ReproOutputs](
		ai.WorkflowRepro,
		"reproduce a kernel crash and generate a syzlang program",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				&aflow.LLMAgent{
					Name:        "crash-repro-finder",
					Model:       aflow.BestExpensiveModel,
					Reply:       "ReproSyz",
					TaskType:    aflow.FormalReasoningTask,
					Instruction: reproInstruction,
					Prompt:      reproPrompt,
					Tools:       append(syzlang.Tools, toolcrash.ReproduceTool, toolcrash.CompareCrashTool),
				},
				crash.Reproduce,
				aflow.Compare("BugTitle", "ReproducedBugTitle", "CrashSignatureMatches"),
			),
		},
	)
}

const reproInstruction = `
You are an expert in linux kernel fuzzing. Your goal is to write a syzkaller program to trigger
a specific bug.

First, search for the relevant syzlang definitions using the syzlang-search tool.
Then, write a candidate .syz test program. Use the syz-compiler-check tool to validate your syntax.
Once compilation passes, use the crash-reproducer tool to run it in the VM.
After that, use compare-crash-signature to verify if the reproduced crash matches the target crash title.

If previous attempts failed, pay attention to the errors and fix them.
Print only the syz program that could be executed directly, without backticks. 
`

const reproPrompt = `
Original Crash Report:
{{.CrashReport}}
`
