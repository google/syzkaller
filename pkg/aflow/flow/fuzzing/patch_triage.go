// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/osutil"
)

func init() {
	aflow.Register[ai.PatchTriageArgs, ai.PatchTriageResult](
		ai.WorkflowPatchTriage,
		"evaluate if a kernel patch series has functional impact worth fuzzing",
		&aflow.Flow{
			Root: aflow.Pipeline(
				readPatchDiff,
				&aflow.LLMAgent{
					Name:     "patch-evaluator",
					Model:    aflow.BestExpensiveModel,
					TaskType: aflow.FormalReasoningTask,
					Outputs: aflow.ValidatedLLMOutputs[ai.PatchTriageResult, struct{}](
						func(ctx *aflow.Context, state struct{}, args ai.PatchTriageResult) (ai.PatchTriageResult, error) {
							if args.Reasoning == "" {
								return args, aflow.BadCallError("reasoning must be provided")
							}
							return args, nil
						},
					),
					Tools: aflow.Tools(
						grepper.Tool,
						codesearcher.FilesystemTools,
					),
					Instruction: patchTriageInstruction,
					Prompt:      patchTriagePrompt,
				},
			),
		},
	)
}

type readPatchDiffArgs struct {
	KernelSrc string
}

type readPatchDiffResult struct {
	PatchDiff string
}

var readPatchDiff = aflow.NewFuncAction("read-patch-diff",
	func(ctx *aflow.Context, args readPatchDiffArgs) (readPatchDiffResult, error) {
		patch, err := osutil.RunCmd(time.Minute, args.KernelSrc, "git", "show", "HEAD")
		if err != nil {
			return readPatchDiffResult{}, err
		}
		return readPatchDiffResult{PatchDiff: string(patch)}, nil
	})

const patchTriageInstruction = `You are an expert Linux kernel maintainer.
Your job is to review a provided patch series and determine
if it makes functional changes to the kernel that should be fuzzed.

IMPORTANT: The changes have ALREADY been applied and committed as the HEAD commit in
your workspace. Do NOT rely on your internal knowledge of the kernel. You must actively
use your code access tools to examine the actual source code and confirm any assumptions.

Return WorthFuzzing=false if the patch only contains:
- Modifications to Documentation/, Kconfig files, or code comments.
- Purely decorative changes, such as logging (e.g., pr_err, printk) or tracepoints.
- Changes to numeric constants or macros that do not functionally alter execution flow.
- Code paths that are impossible to reach in virtualized environments like GCE or QEMU,
even when utilizing software-emulated hardware (e.g., usb gadget, mac80211_hwsim).

If it modifies reachable core kernel logic, drivers, or architectures, use your code search
tools to verify the code can be executed, then return WorthFuzzing=true.`

const patchTriagePrompt = `For your convenience, here is the diff of the changes:
{{.PatchDiff}}`
