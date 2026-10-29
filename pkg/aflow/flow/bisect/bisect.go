// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package bisect provides workflows for AI cause and fix bisection: identification of the
// commit(s) that introduced or fixed a kernel bug, based on the crash report and, if available,
// a root cause analysis.
package bisect

import (
	"fmt"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var codeAccessTools = aflow.Tools(codesearcher.Tools, grepper.Tool, gitlog.Tools)

type CauseInputs struct {
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
	// workflow) and the kernel commit it was done on. If present, the agent verifies
	// and builds on it instead of analyzing the crash from scratch.
	RootCause       string `json:",omitempty"`
	RootCauseCommit string `json:",omitempty"`
}

type FixInputs struct {
	CauseInputs
	// Commit on which the crash occurred; candidate fix commits must not be present in
	// CrashCommit and must be reachable from KernelCommit (the newer branch tip being searched).
	CrashCommit string
}

func init() {
	aflow.Register[CauseInputs, ai.BisectOutputs](
		ai.WorkflowBisectCause,
		"identify the commit that introduced a kernel bug (AI cause bisection)",
		&aflow.Flow{
			Consts: map[string]any{
				"CrashCommit": "",
			},
			Root: bisectPipeline("cause-finder", causeFinderInstruction),
		},
	)
	aflow.Register[FixInputs, ai.BisectOutputs](
		ai.WorkflowBisectFix,
		"identify the commit that fixed a kernel bug (AI fix bisection)",
		&aflow.Flow{
			Root: bisectPipeline("fix-finder", fixFinderInstruction),
		},
	)
}

func bisectPipeline(agentName, instruction string) aflow.Action {
	return aflow.Pipeline(
		actionsyzlang.CreateSimplifiedCRepro,
		kernel.Checkout,
		kernel.Build,
		codesearcher.PrepareIndex,
		&aflow.LLMAgent{
			Name:                agentName,
			Model:               aflow.DeepReasoningModel,
			Reply:               "BisectReasoning",
			Outputs:             aflow.ValidatedLLMOutputs(validateFinderOutputs),
			Instruction:         instruction,
			Prompt:              bisectPrompt,
			Tools:               codeAccessTools,
			MaxIterations:       80,
			AllowPartialResults: true,
		},
		formatBisect,
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
5. Do NOT return a merge commit unless the bug was introduced by the merge conflict
   resolution itself; otherwise identify the underlying non-merge commit(s).
6. Verify your hypothesis by inspecting the full commit diff with {{.toolGitShow}} and
   confirming how the change introduced the exact condition described in the root cause.
` + commonInstructionSuffix

const fixFinderInstruction = `
You are an experienced Linux kernel developer tasked with identifying the commit
that fixed a kernel bug (fix bisection).

The kernel source tree is checked out at a newer commit ({{.KernelCommit}}) where the bug is
believed to be fixed, while the crash occurred on an older commit ({{.CrashCommit}}).

Your investigation strategy:
1. Understand the root cause of the crash at {{.CrashCommit}}.
{{if .RootCause}}   A root cause analysis of the bug is provided; verify its key claims against the source
   code (using {{.toolGitShow}} at {{.CrashCommit}} if the current tree has diverged).
{{else}}   Analyze the crash report and inspect the code it points to (using {{.toolGitShow}} at
   {{.CrashCommit}} when line numbers or functions in the current checkout have drifted from
   the crash report) until you understand the exact invariant violation and execution sequence
   that caused the crash.
{{end}}   Identify the specific functions, structs, locks, or lifecycles involved in the bug.
2. Use git tools ({{.toolGitLog}}, {{.toolGitBlame}}, {{.toolGitShow}}) to examine commits
   after {{.CrashCommit}} that modified the affected functions, structs, or subsystem.
3. Distinguish genuine fixes from unrelated refactorings, renames, or superficial changes.
   A valid fix commit may either directly patch the buggy condition or refactor/remove the
   affected code path so the buggy state can no longer be reached.
4. Do NOT return a merge commit unless the bug was fixed by the merge conflict resolution
   itself; otherwise identify the underlying non-merge commit(s).
5. Verify your hypothesis by inspecting the full commit diff with {{.toolGitShow}} and
   confirming how the change prevents the exact crash condition.
` + commonInstructionSuffix

const commonInstructionSuffix = `{{if titleIsKASANNullDeref .BugTitle}}
Note: under KASAN NULL-derefs on the source level don't happen around the actual 0 address,
they happen on the KASAN shadow memory around address dfff800000000000 or dffffc0000000000.
Don't be confused by that. Look for the line at the top of the report that tells
the access address and size.
{{end}}
Output rules:
- If you can confidently determine the single commit, return its hash in CandidateCommits
  (as a single-element list).
- If multiple commits contributed or you can narrow it down to a small set of candidate
  commits (at most 5), return their hashes in CandidateCommits ordered by relevance: the
  FIRST commit must be the primary commit, followed by the remaining commits in descending
  order of importance/likelihood.
- If you cannot determine the commit with confidence, return an empty CandidateCommits list
  rather than guessing.
- Your text reply must provide a clear bisection log explaining the root cause of the bug,
  the git history you traced, the candidate commits you examined (with their hashes and
  titles), why you ruled out other commits, and how the identified commit(s) introduced or
  fixed the bug.
` + common.InstructionDontMakeAssumptionsAboutSourceCode

const bisectPrompt = `
The crash{{if .CrashCommit}} (on commit {{.CrashCommit}}){{end}} is:

{{.CrashReport}}
{{if .SimplifiedCRepro}}

The following C code is a draft of the syscall sequence that triggers the kernel crash. Keep in mind
that it may lack the precise threading, sandboxing, and some arguments of a working reproducer:

{{.SimplifiedCRepro}}
{{end}}
{{if .RootCause}}

A previous root cause analysis of this bug{{if .RootCauseCommit}} (at commit {{.RootCauseCommit}}){{end}} concluded:

{{.RootCause}}
{{end}}

{{if .CrashCommit -}}
Search for the commit(s) after {{.CrashCommit}} (up to {{.KernelCommit}}) that fixed this bug.
{{- else -}}
Search for the commit(s) that introduced this bug.
{{- end}}
`

const maxCandidateCommits = 5

type finderState struct {
	KernelSrc    string
	KernelCommit string
	CrashCommit  string
}

type finderOutputs struct {
	CandidateCommits []string `jsonschema:"Candidate commit hashes ordered by relevance (primary commit first, or empty)."`
}

// validateFinderOutputs checks structural git properties of the candidate commit
// hashes returned by the LLM: that at most maxCandidateCommits hashes are provided, that each
// hash exists in the repository and is an ancestor of KernelCommit, and (for fix bisection
// when CrashCommit is set) that the commit was not already present in CrashCommit. It does
// not verify that the commit actually introduced or fixed the bug.
func validateFinderOutputs(ctx *aflow.Context, state finderState, args finderOutputs) (
	finderOutputs, error) {
	if len(args.CandidateCommits) == 0 {
		return args, nil
	}
	if len(args.CandidateCommits) > maxCandidateCommits {
		return args, aflow.BadCallError("too many candidate commits (%d); provide at most %d commits or an empty list",
			len(args.CandidateCommits), maxCandidateCommits)
	}
	var canonical []string
	for _, h := range args.CandidateCommits {
		commitHash, err := kernel.ValidateCommit(state.KernelSrc, state.KernelCommit, h)
		if err != nil {
			return args, err
		}
		if state.CrashCommit != "" {
			inCrash, err := vcs.Git{Dir: state.KernelSrc}.ContainedIn(state.CrashCommit, commitHash)
			if err != nil {
				return args, err
			}
			if inCrash {
				return args, aflow.BadCallError(
					"commit %q is already present in the crash commit %v; identify a commit after the crash commit",
					h, state.CrashCommit)
			}
		}
		if !slices.Contains(canonical, commitHash) {
			canonical = append(canonical, commitHash)
		}
	}
	args.CandidateCommits = canonical
	return args, nil
}

type formatBisectArgs struct {
	KernelSrc        string
	CandidateCommits []string
}

type formatBisectResult struct {
	Commits []ai.Commit
}

var formatBisect = aflow.NewFuncAction("format-bisect",
	func(ctx *aflow.Context, args formatBisectArgs) (formatBisectResult, error) {
		if len(args.CandidateCommits) == 0 {
			return formatBisectResult{}, nil
		}
		repo, err := vcs.NewRepo(targets.Linux, "", args.KernelSrc, vcs.OptDontSandbox)
		if err != nil {
			return formatBisectResult{}, err
		}
		var res formatBisectResult
		for _, h := range args.CandidateCommits {
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
