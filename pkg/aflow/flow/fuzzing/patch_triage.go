// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"strings"
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
							if !args.WorthFuzzing && len(args.FocusSymbols) > 0 {
								return args, aflow.BadCallError("FocusSymbols must be empty if WorthFuzzing is false")
							}
							for i, cfg := range args.EnableConfigs {
								args.EnableConfigs[i] = strings.TrimPrefix(cfg, "CONFIG_")
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
tools to verify the code can be executed, then return WorthFuzzing=true.

When returning WorthFuzzing=true, you MUST ALSO:
1. Extract any specific kernel functions that should be heavily fuzzed into FocusSymbols.
   Avoid listing generic hot-path functions to prevent skewed test distributions.
2. Identify any specific CONFIG_ options required to properly test this new/modified feature.
   Go and look into the Kconfig files and check for ifdefs around the code, do not make assumptions.
   Do not list too generic configs (we already have them enabled). Only list those that
   specifically cover the modified code. List them in the EnableConfigs output array,
   and DO NOT add a 'CONFIG_' prefix (e.g., return "NET_IPV4" instead of "CONFIG_NET_IPV4").`

const patchTriagePrompt = `For your convenience, here is the diff of the changes:
{{.PatchDiff}}`
