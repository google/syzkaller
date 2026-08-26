// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/checkpatch"
	"github.com/google/syzkaller/pkg/aflow/tool/clangformat"
	"github.com/google/syzkaller/pkg/aflow/tool/codeeditor"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
)

func patchRefinementLoop(initStyleItems bool) aflow.Action {
	actions := []aflow.Action{applyPatch}
	if initStyleItems {
		actions = append(actions, initStyleItemsAction)
	}
	actions = append(actions,
		runCheckpatch,
		&aflow.DoWhile{
			While:         "NeedRefinement",
			MaxIterations: 5,
			MapOutputs: map[string]string{
				"PatchDiff":        "PatchDiff",
				"TestError":        "TestError",
				"CheckpatchOutput": "CheckpatchOutput",
				"NeedRefinement":   "NeedRefinement",
			},
			Do: aflow.Pipeline(
				&aflow.LLMAgent{
					Name:        "checkpatch-arbiter",
					Model:       aflow.CoreModel,
					Outputs:     aflow.LLMOutputs[checkpatchArbiterOutputs](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: checkpatchArbiterInstruction,
					Prompt:      checkpatchArbiterPrompt,
				},
				evaluateArbiter,
				&aflow.If{
					Condition: "NeedRefinement",
					Do: aflow.Pipeline(
						&aflow.LLMAgent{
							Name:        "patch-formatter",
							Model:       aflow.CoreModel,
							Reply:       "FormatterExplanation",
							TaskType:    aflow.FormalReasoningTask,
							Instruction: formatterInstruction,
							Prompt:      formatterPrompt,
							Tools: aflow.Tools(common.CodeAccessTools, codeeditor.Tool,
								patchdiff.Tool, checkpatch.Tool, clangformat.Tool),
						},
						crash.TestPatchInplace, // -> PatchDiff or TestError
						runCheckpatch,
					),
				},
			),
		},
	)
	return aflow.Pipeline(actions...)
}

type checkpatchArbiterOutputs struct {
	ActionableIssues []string `jsonschema:"List of genuine, fixable style/formatting issues."`
}

var evaluateArbiter = aflow.NewFuncAction("evaluate-checkpatch-arbiter",
	func(ctx *aflow.Context, args struct {
		ActionableIssues []string
		TestError        string
	}) (struct {
		NeedRefinement bool
	}, error) {
		return struct{ NeedRefinement bool }{
			NeedRefinement: len(args.ActionableIssues) > 0 || args.TestError != "",
		}, nil
	})

var initStyleItemsAction = aflow.NewFuncAction("init-style-items", func(ctx *aflow.Context, args struct{}) (struct {
	StyleItems []string
}, error) {
	return struct{ StyleItems []string }{}, nil
})

var applyPatch = aflow.NewFuncAction("apply-patch", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
	PatchDiff        string
}) (struct{}, error) {
	return struct{}{}, applyGitDiff(args.KernelScratchSrc, args.PatchDiff)
})

var runCheckpatch = aflow.NewFuncAction("run-checkpatch", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
}) (struct {
	CheckpatchOutput string
}, error) {
	output, _, err := kernel.Checkpatch(args.KernelScratchSrc)
	if err != nil {
		return struct {
			CheckpatchOutput string
		}{}, err
	}

	return struct {
		CheckpatchOutput string
	}{
		CheckpatchOutput: output,
	}, nil
})

const checkpatchArbiterInstruction = `
You are an expert Linux kernel maintainer acting as a code style arbiter.
Your task is to review scripts/checkpatch.pl output and reviewer style requests for a proposed patch.

Determine which reported issues are genuine, actionable formatting/style defects (e.g. indentation, whitespace,
naming, syntax style) and should be fixed. List them in ActionableIssues.

Ignore issues that are false positives, intentional constructs (e.g. BUG_ON/XA_BUG_ON in test files, macros,
subsystem conventions), or unfixable without breaking code logic or tests. If no issues should be changed,
leave ActionableIssues empty.
`

const checkpatchArbiterPrompt = `
The patch diff is:

{{.PatchDiff}}

{{if .CheckpatchOutput}}
The checkpatch.pl output is:
{{.CheckpatchOutput}}
{{end}}

{{if .StyleItems}}
Reviewers requested the following style items:
{{range .StyleItems}}
- {{.}}
{{end}}
{{end}}

{{if .TestError}}
Previous build/test error:
{{.TestError}}
{{end}}

Carefully evaluate each issue and populate ActionableIssues.
`

const formatterInstruction = `
You are an expert Linux kernel developer tasked with formatting a kernel patch.
Your objective is purely formatting: you must ensure the patch complies with the kernel's coding style,
conforms to the surrounding code rules, and addresses the requested style changes, while preserving the code
logic exactly as it is.
You should stop once the requested formatting changes are done.
Do not question the requested changes unless they are obviously wrong.

WARNING: The {{.toolClangFormat}} tool may break the formatting of the surrounding code (like manual alignment).
Use it with caution. We want to make the change fit into the existing formatting as much as possible.
`

const formatterPrompt = `
The current patch diff is:

{{.PatchDiff}}

{{if .ActionableIssues}}
The following style and formatting issues must be fixed:
{{range .ActionableIssues}}
- {{.}}
{{end}}
{{end}}

{{if .TestError}}
Your previous formatting changes broke the build/test:
{{.TestError}}
Please fix the errors.
{{end}}

{{if .FormatterExplanation}}
Your previous reasoning was:
{{.FormatterExplanation}}
{{end}}

Use the provided tools to format the patch.
`
