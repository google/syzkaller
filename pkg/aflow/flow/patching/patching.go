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
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type Inputs struct {
	ReproOpts       string
	ReproSyz        string
	ReproC          string
	KernelConfig    string
	SyzkallerCommit string

	// Same as in the manager config.
	Syzkaller string
	Image     string
	Type      string
	VM        json.RawMessage

	// Use this fixed based kernel commit (for testing/local running).
	FixedBaseCommit string
	FixedRepository string
}

func createPatchingFlow(name string, summaryWindow int) *aflow.Flow {
	commonTools := slices.Clip(append([]aflow.Tool{codeexpert.Tool, grepper.Tool}, codesearcher.Tools...))
	return &aflow.Flow{
		Name: name,
		Root: aflow.Pipeline(
			baseCommitPicker,
			kernel.Checkout,
			kernel.Build,
			// Ensure we can reproduce the crash (and the build boots).
			crash.Reproduce,
			codesearcher.PrepareIndex,
			&aflow.LLMAgent{
				Name:          "debugger",
				Model:         aflow.BestExpensiveModel,
				Reply:         "BugExplanation",
				TaskType:      aflow.FormalReasoningTask,
				Instruction:   debuggingInstruction,
				Prompt:        debuggingPrompt,
				Tools:         commonTools,
				SummaryWindow: summaryWindow,
			},
			kernel.CheckoutScratch,
			&aflow.DoWhile{
				Do: aflow.Pipeline(
					&aflow.LLMAgent{
						Name:          "patch-generator",
						Model:         aflow.BestExpensiveModel,
						Reply:         "PatchExplanation",
						TaskType:      aflow.FormalReasoningTask,
						Instruction:   patchInstruction,
						Prompt:        patchPrompt,
						Tools:         append(commonTools, codeeditor.Tool),
						SummaryWindow: summaryWindow,
					},
					crash.TestPatch, // -> PatchDiff or TestError
				),
				While:         "TestError",
				MaxIterations: 10,
			},
			getMaintainers,
			getRecentCommits,
			&aflow.LLMAgent{
				Name:          "description-generator",
				Model:         aflow.BestExpensiveModel,
				Reply:         "PatchDescription",
				TaskType:      aflow.FormalReasoningTask,
				Instruction:   descriptionInstruction,
				Prompt:        descriptionPrompt,
				Tools:         commonTools,
				SummaryWindow: summaryWindow,
			},
		),
	}
}

func init() {
	aflow.Register[Inputs, ai.PatchingOutputs](
		ai.WorkflowPatching,
		"generate a kernel patch fixing a provided bug reproducer",
		createPatchingFlow("", 0),
		createPatchingFlow("summary", 10),
	)
}

// TODO: mention not doing assumptions about the source code, and instead querying code using tools.
// TODO: mention to extensively use provided tools to confirm everything.
// TODO: use cause bisection info, if available.

const debuggingInstruction = `
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation. Include all relevant details
into the response: function/struct/field/etc names, code snippets, line numbers,
macro/enum values, etc.

{{if titleIsKASANNullDeref .BugTitle}}
Note: under KASAN NULL-derefs on the source level don't happen around the actual 0 address,
they happen on the KASAN shadow memory around address dfff800000000000 or dffffc0000000000.
Don't be confused by that. Look for the like at the top of the report that tells
the access address and size.
{{end}}
`

const debuggingPrompt = `
The crash is:

{{.CrashReport}}
`

const patchInstruction = `
You are an experienced Linux kernel developer tasked with creating a fix for a kernel bug.
You will be given a crash report, and an initial explanation of the root cause done by another
kernel expert.

Use the codeedit tool to do code edits.
Note: you will not see your changes when looking at the code using codesearch tools.

Your final reply should contain explanation of what you did in the patch and why
(details not present in the initial explanation of the bug).

Your fix must not just prevent the given crash, but also be the best fix for the underlying
root cause from the software engineering point of view. There can be several ways to fix the
same bug. Consider alternatives, and pick the best one. For example, additional checks may be
added at different locations/functions, it's usually better to place them earlier in the
execution to avoid multiple checks at various locations later.

Frequently the same coding mistake is done in several locations in the source code.
Check if your fix should be extended/applied to similar cases around to fix other similar bugs.
But don't go too wide, don't try to fix problems kernel-wide, fix similar issues
in the same file only.

If you are changing post-conditions of a function, consider all callers of the functions,
and if they need to be updated to handle new post-conditions. For example, if you make
a function that previously never returned a NULL, return NULL, consider if callers
need to be updated to handle NULL return value.

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

Here are summaries of recent commits that touched the same files.
Format the summary line consistently with these, look how prefixes
are specified, letter capitalization, style, etc. 

{{.RecentCommits}}

{{if titleIsWarning .BugTitle}}
If the patch removes the WARN_ON macro, refer to the fact that WARN_ON
must not be used for conditions that can legitimately happen, and that pr_err
should be used instead if necessary.
{{end}}
`
