// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package bisect provides workflows for AI cause and fix bisection: identification of the
// commit(s) that introduced or fixed a kernel bug, based on the crash report and, if available,
// a root cause analysis.
package bisect

import (
	"errors"
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

// Inputs holds the inputs common to the bisect-cause and bisect-fix workflows.
type Inputs struct {
	TargetOS     string
	TargetArch   string
	TargetVMArch string `json:",omitempty"`
	BugTitle     string
	CrashReport  string
	ReproSyz     string
	ReproC       string
	KernelRepo   string
	CrashCommit  string
	KernelConfig string
	// Root cause analysis that was already done for the bug (e.g. by the assessment-security
	// workflow) and the kernel commit it was done on. If present, the agent verifies
	// and builds on it instead of analyzing the crash from scratch.
	RootCauseAnalysis string `json:",omitempty"`
	RootCauseCommit   string `json:",omitempty"`
}

type CauseInputs struct {
	Inputs
}

type FixInputs struct {
	Inputs
	// KernelCommit is the newer commit that is checked out and searched up to (e.g. HEAD
	// of the latest kernel build), where the crash has not been observed recently;
	// the bug may or may not be fixed there. Fix candidates must be in CrashCommit..KernelCommit.
	KernelCommit string
}

// useCrashCommit makes cause bisection check out the commit where the crash was observed.
// The shared kernel.Checkout, kernel.Build and codesearcher.PrepareIndex actions consume
// the commit to work on as KernelCommit. For fix bisection, KernelCommit is a separate
// (newer) input, but for cause bisection the commit to check out is CrashCommit itself.
// Since aflow binds state variables by name and cannot alias them, this action
// provides KernelCommit as a copy of CrashCommit.
var useCrashCommit = aflow.NewFuncAction("use-crash-commit",
	func(ctx *aflow.Context, args struct{ CrashCommit string }) (struct{ KernelCommit string }, error) {
		return struct{ KernelCommit string }{args.CrashCommit}, nil
	})

func init() {
	aflow.Register[CauseInputs, ai.BisectCauseOutputs](
		ai.WorkflowBisectCause,
		"identify the commit that introduced a kernel bug (AI cause bisection)",
		&aflow.Flow{
			Root: aflow.Pipeline(useCrashCommit, bisectPipeline(&aflow.LLMAgent{
				Name:        "cause-finder",
				Outputs:     aflow.ValidatedLLMOutputs(validateCauseFinderOutputs),
				Instruction: causeFinderInstruction,
				Prompt:      causeFinderPrompt,
			})),
		},
	)
	aflow.Register[FixInputs, ai.BisectFixOutputs](
		ai.WorkflowBisectFix,
		"identify the commit that fixed a kernel bug, or determine that it is still present (AI fix bisection)",
		&aflow.Flow{
			Root: bisectPipeline(&aflow.LLMAgent{
				Name:        "fix-finder",
				Outputs:     aflow.ValidatedLLMOutputs(validateFixFinderOutputs),
				Instruction: fixFinderInstruction,
				Prompt:      fixFinderPrompt,
			}),
		},
	)
}

// bisectPipeline fills in the agent settings that are common for cause and fix bisection
// and wraps the agent into the shared pipeline.
func bisectPipeline(agent *aflow.LLMAgent) aflow.Action {
	agent.Model = aflow.DeepReasoningModel
	agent.Reply = "BisectReasoning"
	agent.Tools = codeAccessTools
	agent.MaxIterations = 80
	return aflow.Pipeline(
		actionsyzlang.CreateSimplifiedCRepro,
		kernel.Checkout,
		kernel.Build,
		codesearcher.PrepareIndex,
		agent,
		formatBisect,
	)
}

const causeFinderInstruction = `
You are an experienced Linux kernel developer tasked with identifying the commit
that introduced a kernel bug (cause bisection).

Your investigation strategy:
1. Establish the root cause first.
{{if .RootCauseAnalysis}}   A root cause analysis of the bug is provided; verify its key claims against the actual
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
` + kasanNullDerefNote + `
Output rules:
` + candidateOutputRules + common.InstructionDontMakeAssumptionsAboutSourceCode

const fixFinderInstruction = `
You are an experienced Linux kernel developer tasked with determining whether a kernel bug
has been fixed and, if so, identifying the commit that fixed it (fix bisection).

The crash was observed on commit {{.CrashCommit}}. The kernel source tree is checked out at
a newer commit ({{.KernelCommit}}) where the crash has not been observed recently. This does
not mean the bug is fixed: the crash may be rare, or the code may simply not have been
exercised. Determining that the bug is still present at {{.KernelCommit}} is a valid outcome.

Your investigation strategy:
1. Understand the root cause of the crash at {{.CrashCommit}}.
{{if .RootCauseAnalysis}}   A root cause analysis of the bug is provided; verify its key claims against the source
   code (using {{.toolGitShow}} at {{.CrashCommit}} if the current tree has diverged).
{{else}}   Analyze the crash report and inspect the code it points to (using {{.toolGitShow}} at
   {{.CrashCommit}} when line numbers or functions in the current checkout have drifted from
   the crash report) until you understand the exact invariant violation and execution sequence
   that caused the crash.
{{end}}   Identify the specific functions, structs, locks, or lifecycles involved in the bug.
2. Check whether the buggy logic and the execution sequence leading to the crash still exist
   in the current checkout ({{.KernelCommit}}).
3. Use git tools ({{.toolGitLog}}, {{.toolGitBlame}}, {{.toolGitShow}}) to examine commits
   after {{.CrashCommit}} that modified the affected functions, structs, or subsystem.
4. Distinguish genuine fixes from unrelated refactorings, renames, or superficial changes.
   A valid fix commit may either directly patch the buggy condition or refactor/remove the
   affected code path so the buggy state can no longer be reached.
5. Verify your hypothesis by inspecting the full commit diff with {{.toolGitShow}} and
   confirming how the change prevents the exact crash condition.
` + kasanNullDerefNote + `
Output rules:
- If you have verified that the bug is still present at {{.KernelCommit}}, set BugStillPresent
  and return an empty CandidateCommits list. Do NOT set BugStillPresent merely because you
  could not find the fix commit.
` + candidateOutputRules + common.InstructionDontMakeAssumptionsAboutSourceCode

const kasanNullDerefNote = `{{if titleIsKASANNullDeref .BugTitle}}
Note: under KASAN NULL-derefs on the source level don't happen around the actual 0 address,
they happen on the KASAN shadow memory around address dfff800000000000 or dffffc0000000000.
Don't be confused by that. Look for the line at the top of the report that tells
the access address and size.
{{end}}`

const candidateOutputRules = `- If you can confidently determine the single commit, return its hash in CandidateCommits
  (as a single-element list).
- If multiple commits contributed or you can narrow it down to a small set of candidate
  commits (at most 5), return their hashes in CandidateCommits ordered by relevance: the
  FIRST commit must be the primary commit, followed by the remaining commits in descending
  order of importance/likelihood.
- If you cannot determine the commit with confidence, return an empty CandidateCommits list
  rather than guessing.
- Your text reply must provide a clear bisection log explaining the root cause of the bug,
  the git history you traced, the candidate commits you examined (with their hashes and
  titles), why you ruled out other commits, and how you reached your conclusion.
`

const causeFinderPrompt = `
The crash is:
` + crashDetailsPrompt + `
Search for the commit(s) that introduced this bug.
`

const fixFinderPrompt = `
The crash, observed on commit {{.CrashCommit}}, is:
` + crashDetailsPrompt + `
Determine whether this bug is still present at {{.KernelCommit}} and, if it was fixed,
search for the commit(s) after {{.CrashCommit}} that fixed it.
`

const crashDetailsPrompt = `
{{.CrashReport}}
{{if .SimplifiedCRepro}}

The following C code is a draft of the syscall sequence that triggers the kernel crash. Keep in mind
that it may lack the precise threading, sandboxing, and some arguments of a working reproducer:

{{.SimplifiedCRepro}}
{{end}}
{{if .RootCauseAnalysis}}

A previous root cause analysis of this bug{{if .RootCauseCommit}} (at commit {{.RootCauseCommit}}){{end}} concluded:

{{.RootCauseAnalysis}}
{{end}}
`

const maxCandidateCommits = 5

type causeFinderState struct {
	KernelSrc    string
	KernelCommit string
}

type causeFinderOutputs struct {
	CandidateCommits []string `jsonschema:"Candidate commit hashes ordered by relevance (primary commit first, or empty)."`
}

func validateCauseFinderOutputs(ctx *aflow.Context, state causeFinderState, args causeFinderOutputs) (
	causeFinderOutputs, error) {
	commits, err := validateCandidateCommits(state.KernelSrc, state.KernelCommit, "", args.CandidateCommits)
	args.CandidateCommits = commits
	return args, err
}

type fixFinderState struct {
	KernelSrc    string
	KernelCommit string
	CrashCommit  string
}

type fixFinderOutputs struct {
	BugStillPresent  bool     `jsonschema:"Set if the bug is verified to still be present at the current commit."`
	CandidateCommits []string `jsonschema:"Candidate commit hashes ordered by relevance (primary commit first, or empty)."`
}

func validateFixFinderOutputs(ctx *aflow.Context, state fixFinderState, args fixFinderOutputs) (
	fixFinderOutputs, error) {
	if state.CrashCommit == "" {
		return args, errors.New("CrashCommit must not be empty")
	}
	if args.BugStillPresent {
		if len(args.CandidateCommits) != 0 {
			return args, aflow.BadCallError("CandidateCommits must be empty when BugStillPresent is set")
		}
		return args, nil
	}
	commits, err := validateCandidateCommits(state.KernelSrc, state.KernelCommit, state.CrashCommit,
		args.CandidateCommits)
	args.CandidateCommits = commits
	return args, err
}

// validateCandidateCommits checks structural git properties of the candidate commit hashes
// returned by the LLM: that at most maxCandidateCommits hashes are provided, that each hash
// exists in the repository and is an ancestor of kernelCommit, and (if crashCommit is set)
// that the commit was not already present in crashCommit. It returns the canonical,
// deduplicated hashes in the original order. It does not verify that the commits actually
// introduced or fixed the bug.
func validateCandidateCommits(kernelSrc, kernelCommit, crashCommit string, hashes []string) ([]string, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	if len(hashes) > maxCandidateCommits {
		return hashes, aflow.BadCallError("too many candidate commits (%d); provide at most %d commits or an empty list",
			len(hashes), maxCandidateCommits)
	}
	var canonical []string
	for _, h := range hashes {
		commitHash, err := kernel.ValidateCommit(kernelSrc, kernelCommit, h)
		if err != nil {
			return hashes, err
		}
		if crashCommit != "" {
			inCrash, err := vcs.SandboxedGit(kernelSrc).ContainedIn(crashCommit, commitHash)
			if err != nil {
				return hashes, err
			}
			if inCrash {
				return hashes, aflow.BadCallError(
					"commit %q is already present in the crash commit %v; identify a commit after the crash commit",
					h, crashCommit)
			}
		}
		if !slices.Contains(canonical, commitHash) {
			canonical = append(canonical, commitHash)
		}
	}
	return canonical, nil
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
		repo, err := vcs.NewRepo(targets.Linux, "", args.KernelSrc)
		if err != nil {
			return formatBisectResult{}, err
		}
		var res formatBisectResult
		for _, h := range args.CandidateCommits {
			com, err := repo.Commit(h)
			if err != nil {
				return res, fmt.Errorf("failed to get commit %q: %w", h, err)
			}
			var recipients []ai.Recipient
			for _, r := range com.Recipients {
				recipients = append(recipients, ai.Recipient{
					Name:  r.Address.Name,
					Email: r.Address.Address,
					To:    r.Type == vcs.To,
				})
			}
			res.Commits = append(res.Commits, ai.Commit{
				Hash:        com.Hash,
				Title:       com.Title,
				AuthorName:  com.AuthorName,
				AuthorEmail: com.Author,
				Date:        com.Date,
				Recipients:  recipients,
			})
		}
		return res, nil
	})
