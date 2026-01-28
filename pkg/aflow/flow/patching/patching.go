// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"encoding/json"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codeeditor"
	"github.com/google/syzkaller/pkg/aflow/tool/codeexpert"
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
	FixedRepository string
}

type Outputs struct {
	// Base repo/commit for the patch.
	KernelRepo       string
	KernelCommit     string
	PatchDescription string
	PatchDiff        string
	Recipients       []Recipient
}

type Recipient struct {
	Name  string
	Email string
	To    bool // whether the recipient should be on the To or Cc line
}

func init() {
	commonTools := slices.Clip(append([]aflow.Tool{codeexpert.Tool}, codesearcher.Tools...))

	aflow.Register[Inputs, Outputs](
		ai.WorkflowPatching,
		"generate a kernel patch fixing a provided bug reproducer",
		&aflow.Flow{
			Root: aflow.Pipeline(
				baseCommitPicker,
				kernel.Checkout,
				kernel.Build,
				// Ensure we can reproduce the crash (and the build boots).
				crash.Reproduce,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:        "debugger",
					Model:       aflow.BestExpensiveModel,
					Reply:       "BugExplanation",
					Temperature: 1,
					Instruction: debuggingInstruction,
					Prompt:      debuggingPrompt,
					Tools:       commonTools,
				},
				kernel.CheckoutScratch,
				&aflow.DoWhile{
					Do: aflow.Pipeline(
						&aflow.LLMAgent{
							Name:        "patch-generator",
							Model:       aflow.BestExpensiveModel,
							Reply:       "PatchExplanation",
							Temperature: 1,
							Instruction: patchInstruction,
							Prompt:      patchPrompt,
							Tools:       append(commonTools, codeeditor.Tool),
						},
						crash.TestPatch, // -> PatchDiff or TestError
					),
					While:         "TestError",
					MaxIterations: 10,
				},
				getMaintainers,
				&aflow.LLMAgent{
					Name:        "description-generator",
					Model:       aflow.BestExpensiveModel,
					Reply:       "PatchDescription",
					Temperature: 1,
					Instruction: descriptionInstruction,
					Prompt:      descriptionPrompt,
					Tools:       commonTools,
				},
			),
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
`

const debuggingPrompt = `
The crash is:

{{.CrashReport}}
`

const patchInstruction = `
You are an experienced Linux kernel developer tasked with creating a fix for a kernel bug.
Use the codeedit tool to do code edits.
Note: you will not see your changes when looking at the code using codesearch tools.
Your final reply should contain explanation of what you did in the patch and why.

{{if titleIsWarning .BugTitle}}
If you will end up removing the WARN_ON macro because the condition can legitimately happen,
add a pr_err call that logs that the unlikely condition has happened. The pr_err message
must not include "WARNING" string.
{{end}}
`

const patchPrompt = `
The crash that corresponds to the bug is:

{{.CrashReport}}

The explanation of the root cause of the bug is:

{{.BugExplanation}}

{{if .TestError}}

Another developer tried to fix this bug, and come up with the following strategy for fixing:

{{.PatchExplanation}}

{{/* A TestError without PatchDiff means the previous invocation did not generate any patch. */}}
{{if .PatchDiff}}
and the following patch:

{{.PatchDiff}}

However, the patch testing failed with the following error:

{{.TestError}}

If the error is fixable, and the fix patch is correct overall,
the create a new fixed patch based on the provided one with the errors fixed.
If the error points to a fundamental issue with the approach in the patch,
then create a new patch from scratch.
Note: in both cases the source tree does not contain the patch yet
(so if you want to create a new fixed patch, you need to recreate it
in its entirety from scratch using the codeeditor tool).
{{else}}
If the strategy looks reasonable to you, proceed with patch generation.
{{end}}
{{end}}
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

Additional description of the patch:

{{.PatchExplanation}}

{{if titleIsWarning .BugTitle}}
If the patch removes the WARN_ON macro, refer to the fact that WARN_ON
must not be used for conditions that can legitimately happen, and that pr_err
should be used instead if necessary.
{{end}}
`
