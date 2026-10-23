// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package bisectcause provides a workflow for AI cause bisection: identification of the commit(s)
// that introduced a kernel bug, based on the crash report and, if available, a root cause analysis.
package bisectcause

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var codeAccessTools = aflow.Tools(codesearcher.Tools, grepper.Tool, gitlog.Tools)

type Inputs struct {
	TargetOS     string
	TargetArch   string
	TargetVMArch string `json:",omitempty"`
	BugTitle     string
	CrashReport  string
	ReproSyz     string
	ReproC       string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	// Root cause analysis that was already done for the bug (e.g. by the assessment-security
	// workflow) and the kernel commit it was done on. If present, the cause-finder verifies
	// and builds on it instead of analyzing the crash from scratch.
	RootCause       string `json:",omitempty"`
	RootCauseCommit string `json:",omitempty"`
}

func init() {
	aflow.Register[Inputs, ai.BisectCauseOutputs](
		ai.WorkflowBisectCause,
		"identify the commit that introduced a kernel bug (AI cause bisection)",
		&aflow.Flow{
			Root: aflow.Pipeline(
				actionsyzlang.CreateSimplifiedCRepro,
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:                "cause-finder",
					Model:               aflow.DeepReasoningModel,
					Reply:               "BisectReasoningRaw",
					Outputs:             aflow.ValidatedLLMOutputs[causeFinderArgs](validateCauseFinderOutputs),
					Instruction:         causeFinderInstruction,
					Prompt:              causeFinderPrompt,
					Tools:               codeAccessTools,
					MaxIterations:       80,
					AllowPartialResults: true,
				},
				formatBisectCause,
			),
		},
	)
}

const causeFinderInstruction = `
You are an experienced Linux kernel developer tasked with identifying the commit
that introduced a kernel bug (cause bisection).

Your investigation strategy:
1. Establish the root cause first.
{{if .RootCause}}   A root cause analysis of the bug is provided; verify its key claims against the actual
   source code before relying on it.
{{else}}   Analyze the crash report and the code it points to (stack traces, allocation/free stacks,
   the involved functions and structs) until you understand the exact invariant that is
   violated and the exact execution sequence that leads to the crash.
{{end}}   Identify the specific functions, structs, invariants, or lines of code where the buggy
   logic resides.
2. Use git tools ({{.toolGitBlame}}, {{.toolGitLog}}, {{.toolGitShow}}) to trace the history
   of the affected functions and lines.
3. Trace past pure refactorings, code movements, formatting changes, or variable renames
   to find the commit that actually introduced the buggy logic or broke an existing invariant.
4. Do NOT blame commits that merely added debugging or sanitizer checks (WARN_ON, BUG_ON,
   KASAN/KMSAN/LOCKDEP annotations) that exposed an older bug, unless the check itself is
   incorrect and is the bug.
5. Do NOT return merge commits or release tag commits; always identify the underlying
   non-merge commit(s).
6. Verify your hypothesis by inspecting the full commit diff with {{.toolGitShow}} and
   confirming how the change introduced the exact condition described in the root cause.
{{if titleIsKASANNullDeref .BugTitle}}
Note: under KASAN NULL-derefs on the source level don't happen around the actual 0 address,
they happen on the KASAN shadow memory around address dfff800000000000 or dffffc0000000000.
Don't be confused by that. Look for the line at the top of the report that tells
the access address and size.
{{end}}
Output rules:
{{if not .RootCause}}- RootCauseSummaryRaw must be a short (up to 4-5 sentences) summary of the root cause
  and its direct impact, suitable for a bug report.
- RootCauseAnalysisRaw must be a detailed explanation of the root cause of the bug. Include
  all relevant details: function/struct/field names, file paths, code snippets, line numbers,
  macro/enum values, and the exact execution sequence that leads to the crash.
{{end}}- If you can confidently determine the single commit that introduced the bug, return its
  hash in CommitHashes (as a single-element list).
- If you can narrow the bug introduction down to a small set of candidate commits (at most 5)
  but cannot conclusively distinguish between them from static analysis alone, return those
  candidate hashes in CommitHashes.
- If you cannot determine the bug-introducing commit with confidence, return an empty
  CommitHashes list rather than guessing.
- Your text reply must provide a clear bisection log explaining the git history you traced,
  the candidate commits you examined (with their hashes and titles), why you ruled out other
  commits, and how the identified commit(s) introduced the bug.
` + common.InstructionDontMakeAssumptionsAboutSourceCode

const causeFinderPrompt = `
The crash is:

{{.CrashReport}}
{{if .SimplifiedCRepro}}

The following C code is a draft of the vulnerable syscall sequence. Keep in mind that
it may lack the precise threading, sandboxing, and some arguments of a working reproducer:

{{.SimplifiedCRepro}}
{{end}}
{{if .RootCause}}

A previous root cause analysis of this bug{{if .RootCauseCommit}} (at commit {{.RootCauseCommit}}){{end}} concluded:

{{.RootCause}}
{{end}}

Search for the commit(s) that introduced this bug.
`

const maxCauseCommits = 5

type causeFinderState struct {
	KernelSrc    string
	KernelCommit string
	RootCause    string
}

type causeFinderArgs struct {
	RootCauseSummaryRaw  string   `json:",omitempty" jsonschema:"Short summary of the root cause and its direct impact."`
	RootCauseAnalysisRaw string   `json:",omitempty" jsonschema:"Detailed explanation of the root cause of the bug."`
	CommitHashes         []string `jsonschema:"Commit hashes that introduced the bug (1, multiple, or empty)."`
}

// validateCauseFinderOutputs checks that a root cause summary and analysis are provided when
// no RootCause input was given, and checks structural git properties of the candidate commit
// hashes returned by the LLM: that at most maxCauseCommits hashes are provided, and that each
// hash exists in the repository, is an ancestor of KernelCommit, and is neither a merge commit
// nor a release tag. It does not verify that the commit actually introduced the bug.
func validateCauseFinderOutputs(ctx *aflow.Context, state causeFinderState, args causeFinderArgs) (
	causeFinderArgs, error) {
	args.RootCauseSummaryRaw = strings.TrimSpace(args.RootCauseSummaryRaw)
	args.RootCauseAnalysisRaw = strings.TrimSpace(args.RootCauseAnalysisRaw)
	if state.RootCause == "" {
		if args.RootCauseSummaryRaw == "" {
			return args, aflow.BadCallError("RootCauseSummaryRaw must not be empty")
		}
		if args.RootCauseAnalysisRaw == "" {
			return args, aflow.BadCallError("RootCauseAnalysisRaw must not be empty")
		}
	}
	if len(args.CommitHashes) == 0 {
		return args, nil
	}
	if len(args.CommitHashes) > maxCauseCommits {
		return args, aflow.BadCallError("too many candidate commits (%d); provide at most %d commits or an empty list",
			len(args.CommitHashes), maxCauseCommits)
	}
	repo, err := vcs.NewRepo(targets.Linux, "", state.KernelSrc, vcs.OptDontSandbox)
	if err != nil {
		return args, err
	}
	git := vcs.Git{Dir: state.KernelSrc}
	var canonical []string
	for _, h := range args.CommitHashes {
		if h == "" {
			return args, aflow.BadCallError("commit hash must not be empty")
		}
		commit, err := repo.Commit(h)
		if err != nil {
			return args, aflow.BadCallError("commit hash %q not found in the repository", h)
		}
		reachable, err := git.ContainedIn(state.KernelCommit, commit.Hash)
		if err != nil || !reachable {
			return args, aflow.BadCallError("commit %q is not reachable from the current commit", h)
		}
		if len(commit.Parents) > 1 {
			return args, aflow.BadCallError("commit %q is a merge commit; identify the non-merge commit that introduced the bug",
				h)
		}
		if bisecter, ok := repo.(vcs.Bisecter); ok {
			if isRelease, err := bisecter.IsRelease(commit.Hash); err == nil && isRelease {
				return args, aflow.BadCallError("commit %q is a release commit; identify the actual commit that introduced the bug",
					h)
			}
		}
		if !slices.Contains(canonical, commit.Hash) {
			canonical = append(canonical, commit.Hash)
		}
	}
	args.CommitHashes = canonical
	return args, nil
}

const rootCauseLineLength = 80

type formatBisectCauseArgs struct {
	KernelSrc            string
	RootCause            string
	RootCauseSummaryRaw  string
	RootCauseAnalysisRaw string
	BisectReasoningRaw   string
	CommitHashes         []string
}

type formatBisectCauseResult struct {
	RootCauseSummary  string
	RootCauseAnalysis string
	BisectReasoning   string
	Commits           []ai.Commit
}

var formatBisectCause = aflow.NewFuncAction("format-bisect-cause",
	func(ctx *aflow.Context, args formatBisectCauseArgs) (formatBisectCauseResult, error) {
		analysisRaw := args.RootCauseAnalysisRaw
		if analysisRaw == "" {
			analysisRaw = args.RootCause
		}
		res := formatBisectCauseResult{
			RootCauseSummary:  email.WordWrap(args.RootCauseSummaryRaw, rootCauseLineLength),
			RootCauseAnalysis: email.WordWrap(analysisRaw, rootCauseLineLength),
			BisectReasoning:   email.WordWrap(args.BisectReasoningRaw, rootCauseLineLength),
		}
		if len(args.CommitHashes) == 0 {
			return res, nil
		}
		repo, err := vcs.NewRepo(targets.Linux, "", args.KernelSrc, vcs.OptDontSandbox)
		if err != nil {
			return res, err
		}
		for _, h := range args.CommitHashes {
			com, err := repo.Commit(h)
			if err != nil {
				return res, fmt.Errorf("failed to get commit %q: %w", h, err)
			}
			// Extract commit recipients into the job output; dashboard does not
			// CC them on bug reports yet until AI bisection is confirmed reliable.
			var recipients []ai.Recipient
			for _, r := range com.Recipients {
				recipients = append(recipients, ai.Recipient{
					Name:  r.Address.Name,
					Email: r.Address.Address,
					To:    r.Type == vcs.To,
				})
			}
			res.Commits = append(res.Commits, ai.Commit{
				Hash:       com.Hash,
				Title:      com.Title,
				Author:     com.Author,
				AuthorName: com.AuthorName,
				Date:       com.Date,
				Recipients: recipients,
			})
		}
		return res, nil
	})
