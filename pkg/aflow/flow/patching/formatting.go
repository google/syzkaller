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
		actions = append(actions, aflow.NewFuncAction("init-style-items", func(ctx *aflow.Context, args struct{}) (struct {
			StyleItems []string
		}, error) {
			return struct{ StyleItems []string }{}, nil
		}))
	}
	actions = append(actions,
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
					Name:        "patch-formatter",
					Model:       aflow.GoodBalancedModel,
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
	)
	return aflow.Pipeline(actions...)
}

var applyPatch = aflow.NewFuncAction("apply-patch", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
	PatchDiff        string
}) (struct{}, error) {
	return struct{}{}, applyGitDiff(args.KernelScratchSrc, args.PatchDiff)
})

var runCheckpatch = aflow.NewFuncAction("run-checkpatch", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
	TestError        string
}) (struct {
	CheckpatchOutput string
	NeedRefinement   bool
}, error) {
	output, hasErrors, err := kernel.Checkpatch(args.KernelScratchSrc)
	if err != nil {
		return struct {
			CheckpatchOutput string
			NeedRefinement   bool
		}{}, err
	}

	return struct {
		CheckpatchOutput string
		NeedRefinement   bool
	}{
		CheckpatchOutput: output,
		NeedRefinement:   hasErrors || args.TestError != "",
	}, nil
})

const formatterInstruction = `
You are an expert Linux kernel developer tasked with formatting a kernel patch.
Your objective is purely formatting: you must ensure the patch complies with the kernel's coding style,
conforms to the surrounding code rules, and passes checkpatch.pl, while preserving the code logic exactly as it is.
You should stop once the requested formatting changes are done and checkpatch.pl is happy.
Do not question the requested changes unless they are obviously wrong.
If the code already conforms to the requested changes, surrounding code rules,
and checkpatch.pl is happy, you should just finish your task.

WARNING: The {{.toolClangFormat}} tool may break the formatting of the surrounding code (like manual alignment).
Use it with caution. We want to make the change fit into the existing formatting as much as possible.
`

const formatterPrompt = `
The current patch diff is:

{{.PatchDiff}}

{{if .StyleItems}}
The reviewers requested the following style changes:
{{range .StyleItems}}
- {{.}}
{{end}}
{{end}}

{{if .CheckpatchOutput}}
The checkpatch.pl output is:
{{.CheckpatchOutput}}
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
