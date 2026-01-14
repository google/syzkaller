// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type Inputs struct {
	ReproOpts         string
	ReproSyz          string
	ReproC            string
	KernelConfig      string
	SyzkallerCommit   string
	CodesearchToolBin string

	// Same as in the manager config.
	Syzkaller string
	Image     string
	Type      string
	VM        json.RawMessage

	// Use this fixed based kernel commit (for testing/local running).
	FixedBaseCommit string
}

type Outputs struct {
	PatchDescription string
	PatchDiff        string
}

func init() {
	tools := codesearcher.Tools

	aflow.Register[Inputs, Outputs](
		ai.WorkflowPatching,
		"generate a kernel patch fixing a provided bug reproducer",
		&aflow.Flow{
			Model: aflow.BestExpensiveModel,
			Root: &aflow.Pipeline{
				Actions: []aflow.Action{
					baseCommitPicker,
					kernel.Checkout,
					kernel.Build,
					// Ensure we can reproduce the crash (and the build boots).
					crash.Reproduce,
					codesearcher.PrepareIndex,
					&aflow.LLMAgent{
						Name:        "debugger",
						Reply:       "BugExplanation",
						Temperature: 1,
						Instruction: debuggingInstruction,
						Prompt:      debuggingPrompt,
						Tools:       tools,
					},
					&aflow.LLMAgent{
						Name:        "diff-generator",
						Reply:       "PatchDiff",
						Temperature: 1,
						Instruction: diffInstruction,
						Prompt:      diffPrompt,
						Tools:       tools,
					},
					&aflow.LLMAgent{
						Name:        "description-generator",
						Reply:       "PatchDescription",
						Temperature: 1,
						Instruction: descriptionInstruction,
						Prompt:      descriptionPrompt,
					},
				},
			},
		},
	)
}

// TODO: mention not doing assumptions about the source code, and instead querying code using tools.
// TODO: mention to extensively use provided tools to confirm everything.
// TODO: use cause bisection info, if available.

const debuggingInstruction = `
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation.
Your final reply must contain only the explanation.

Call some codesearch tools first.
`

const debuggingPrompt = `
The crash is:

{{.CrashReport}}
`

const diffInstruction = `
You are an experienced Linux kernel developer tasked with creating a patch for a kernel bug.
Your final reply should contain only the code diff in patch format.
`

const diffPrompt = `
The crash that corresponds to the bug is:

{{.CrashReport}}

The explanation of the root cause of the bug is:

{{.BugExplanation}}
`

const descriptionInstruction = `
You are an experienced Linux kernel developer tasked with writing a commit description for
a kernel bug fixing commit. The description should start with a one-line summary,
and then include description of the bug being fixed, and how it's fixed by the provided patch.
Your final reply should contain only the text of the commit description.
Phrase the one-line summary so that it is not longer than 72 characters.
The rest of the description must be word-wrapped at 72 characters.
`

const descriptionPrompt = `
The crash that corresponds to the bug is:

{{.CrashReport}}

The explanation of the root cause of the bug is:

{{.BugExplanation}}

The diff of the bug fix is:

{{.PatchDiff}}
`
