// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/osutil"
)

func init() {
	aflow.Register[ai.FindingTriageArgs, ai.FindingTriageResult](
		ai.WorkflowFindingTriage,
		"evaluate if a kernel crash finding was introduced by the patch series",
		&aflow.Flow{
			Root: aflow.Pipeline(
				prepareFindingOverview,
				&aflow.LLMAgent{
					Name:     "finding-triage-evaluator",
					Model:    aflow.CoreModel,
					TaskType: aflow.FormalReasoningTask,
					Outputs: aflow.ValidatedLLMOutputs[ai.FindingTriageResult](
						func(ctx *aflow.Context, state ai.FindingTriageArgs,
							args ai.FindingTriageResult) (ai.FindingTriageResult, error) {
							if args.Reasoning == "" {
								return args, aflow.BadCallError("reasoning must be provided")
							}
							return args, nil
						},
					),
					Tools: aflow.Tools(
						grepper.Tool,
						codesearcher.FilesystemTools,
						ToolSeriesPatches,
						gitlog.ToolShow,
						gitlog.ToolBlame,
					),
					Instruction: findingTriageInstruction,
					Prompt:      findingTriagePrompt,
				},
			),
		},
	)
}

type prepareFindingOverviewArgs struct {
	KernelSrc string
	Patches   []ai.SeriesPatch
}

type prepareFindingOverviewResult struct {
	DiffStat   string
	PatchList  string
	PatchCount int
}

var prepareFindingOverview = aflow.NewFuncAction("prepare-finding-overview",
	func(ctx *aflow.Context, args prepareFindingOverviewArgs) (prepareFindingOverviewResult, error) {
		res := prepareFindingOverviewResult{
			PatchCount: len(args.Patches),
		}

		if args.KernelSrc != "" {
			cmd := osutil.Command("git", "show", "--stat", "--format=", "HEAD")
			cmd.Dir = args.KernelSrc
			if err := osutil.Sandbox(cmd, true, true); err != nil {
				return res, err
			}
			out, err := osutil.Run(time.Minute, cmd)
			if err == nil {
				res.DiffStat = strings.TrimSpace(string(out))
			}
		}

		if len(args.Patches) > 0 {
			var b strings.Builder
			for _, p := range args.Patches {
				fmt.Fprintf(&b, "[%d] %s\n", p.Seq, p.Title)
			}
			res.PatchList = strings.TrimSpace(b.String())
		}

		return res, nil
	})

const findingTriageInstruction = `You are an expert Linux kernel maintainer and security engineer specializing
in crash triage and root-cause analysis.
Your job is to review a kernel crash report (finding) and determine if it was introduced / caused
by the patch series being tested, or if it is a pre-existing / unrelated bug.

IMPORTANT: The entire patch series has ALREADY been applied and committed as a single squashed commit
at HEAD (or on top of the base commit) in your workspace.
Do NOT rely on your internal knowledge of the kernel. You must actively use your tools to examine
the source code, inspect workspace diffs, and confirm any assumptions.

Available Tools:
- {{.toolGitShow}}: View the squashed patch series commit or historical commits. Call with Commit="HEAD" (default)
  and optional 'File' parameter to restrict the diff to a specific file or directory, or 'Stat=true' for a diffstat.
- {{.toolSeriesPatches}}: Browse the original patch series. Call without arguments to list all patch titles,
  or PatchNum=<N> (0 for cover letter, 1..N for patches) to view the full description and diff of patch N.
- {{.toolReadFile}} & {{.toolCodesearchDirIndex}}: Read exact source code files and directory contents in the workspace.
- {{.toolGrepper}}: Regex search across files in the workspace (git grep).
- {{.toolGitBlame}}: Inspect line authorship and find which commit last modified specific lines of code.

Triage Procedure:
1. Analyze the Crash Report:
   - Identify the crash type (e.g. NULL dereference, KASAN use-after-free, out-of-bounds read/write,
     assertion failure, deadlock).
   - Carefully examine the stack trace(s) — both the faulting call stack and, if applicable (e.g., KASAN UAF),
     the allocation and free stacks.
   - Note the faulting function, file name, line numbers, and the specific variables or data structures involved.

2. Inspect Workspace Changes & Patch Series:
   - Check if any files or functions from the stack trace appear in the modified files overview or the patch series.
   - Use {{.toolGitShow}} with Commit="HEAD" and 'File' to inspect the exact diffs for relevant files
     in the squashed commit.
   - If needed, use {{.toolSeriesPatches}} with PatchNum=<N> to inspect the author's commit description
     and rationale for individual patches in the series.
   - Use {{.toolReadFile}} to inspect the actual source code at the faulting lines.

3. Determine Causality:
   - Set Introduced=true ONLY IF you are absolutely certain:
     * There is clear, unambiguous, and conclusive evidence that the crash was directly introduced
       or caused by the patch series.
     * The crash occurs directly in new or modified code introduced by the patch series, or the patch series
       altered data structures, locking, object lifetimes, or preconditions in a way that directly
       triggered the failure in existing code.
   - Set Introduced=false IF:
     * There is any doubt, ambiguity, or lack of conclusive proof that the patch series caused the bug.
     * The crash occurs in an unrelated subsystem or unmodified code path whose behavior is independent
       of the patch series.
     * The crash is a pre-existing kernel issue that was randomly triggered during fuzzing.

4. Formulate Output:
   - Set Introduced to true or false.
   - In Reasoning, provide a clear, step-by-step technical explanation detailing the crash type,
     the key stack frames, whether the affected code/structures were modified by the patch series,
     and the causal justification for your verdict.`

const findingTriagePrompt = `The kernel crash report to triage is:

{{.CrashReport}}

{{if .DiffStat}}
Overview of modified files in the workspace:
{{.DiffStat}}
{{end}}

{{if le .PatchCount 10}}
Patch series commits:
{{.PatchList}}
{{else}}
The patch series contains {{.PatchCount}} commits. Use {{.toolSeriesPatches}} to inspect
individual patches (0 for cover letter, 1..N for patches).
{{end}}`
