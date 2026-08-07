// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

type FailedAttempt struct {
	Strategy string
	Diff     string
	Error    string
}

type recordFailedAttemptArgs struct {
	TestError        string
	PatchExplanation string
	PatchDiff        string
	FailedAttempts   []FailedAttempt
}

type recordFailedAttemptResult struct {
	FailedAttempts []FailedAttempt
}

var recordFailedAttempt = aflow.NewFuncAction("recordFailedAttempt", recordFailedAttemptImpl)

func recordFailedAttemptImpl(ctx *aflow.Context, args recordFailedAttemptArgs) (recordFailedAttemptResult, error) {
	if args.TestError == "" {
		return recordFailedAttemptResult{FailedAttempts: args.FailedAttempts}, nil
	}

	attempts := slices.Clone(args.FailedAttempts)
	attempts = append(attempts, FailedAttempt{
		Strategy: strings.TrimSpace(args.PatchExplanation),
		Diff:     strings.TrimSpace(args.PatchDiff),
		Error:    strings.TrimSpace(args.TestError),
	})

	return recordFailedAttemptResult{FailedAttempts: attempts}, nil
}

type viewFailedAttemptsArgs struct {
	AttemptIndex int `json:",omitempty" jsonschema:"1-based index of the failed attempt to view. 0 for summary."`
}

type viewFailedAttemptsResult struct {
	Result string `jsonschema:"The requested failed attempt information."`
}

var viewFailedAttemptsTool = aflow.NewFuncTool("view-failed-attempts", viewFailedAttemptsToolImpl,
	"View previous failed attempts to fix the bug, including their strategies, diffs, and resulting errors.")

func viewFailedAttemptsToolImpl(ctx *aflow.Context, state struct {
	FailedAttempts []FailedAttempt
}, args viewFailedAttemptsArgs) (viewFailedAttemptsResult, error) {
	if len(state.FailedAttempts) == 0 {
		return viewFailedAttemptsResult{"No failed attempts yet."}, nil
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("There are %d previous failed attempts:\n", len(state.FailedAttempts)))
	for i, attempt := range state.FailedAttempts {
		// Truncate strategy and error for the summary.
		strategy := attempt.Strategy
		if len(strategy) > 100 {
			strategy = strategy[:100] + "..."
		}
		errStr := attempt.Error
		if len(errStr) > 100 {
			errStr = errStr[:100] + "..."
		}
		summary.WriteString(fmt.Sprintf("Attempt %d:\n  Strategy: %s\n  Error: %s\n", i+1, strategy, errStr))
	}
	summary.WriteString("Call this tool with a specific AttemptIndex to see its full strategy, diff, and error.")

	if args.AttemptIndex == 0 {
		return viewFailedAttemptsResult{summary.String()}, nil
	}

	if args.AttemptIndex < 1 || args.AttemptIndex > len(state.FailedAttempts) {
		return viewFailedAttemptsResult{fmt.Sprintf("Note: the specified attempt index (%d) is not found.\n\n%s",
			args.AttemptIndex, summary.String())}, nil
	}

	attempt := state.FailedAttempts[args.AttemptIndex-1]
	return viewFailedAttemptsResult{fmt.Sprintf("Attempt %d\n\nStrategy:\n%s\n\nDiff:\n%s\n\nError:\n%s\n",
		args.AttemptIndex, attempt.Strategy, attempt.Diff, attempt.Error)}, nil
}
