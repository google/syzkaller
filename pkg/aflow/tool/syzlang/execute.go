// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"regexp"
	"strconv"
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzlang"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

var (
	ExecuteSeed = aflow.NewFuncTool("execute-seed", executeSeed, `
Tool executes the given syz program in a VM to collect coverage.
It allows calls to block without hanging the execution by running in threaded mode.
It returns an ExecutionCachedID even if the execution times out or doesn't crash.
`)

	GetExecutedProgram = aflow.NewFuncTool("get-executed-program", getExecutedProgram, `
Tool returns the syzlang program that was executed for the given ExecutionCachedID.
`)
)

type ExecuteSeedArgs struct {
	BaseTestSeed string `jsonschema:"Optional path to a test seed file." json:",omitempty"`
	ReproSyz     string `jsonschema:"Syz program to execute. Appended to BaseTestSeed if provided." json:",omitempty"`
}

type CallError struct {
	Index    int    `jsonschema:"0-based index of the failed syscall."`
	CallName string `jsonschema:"Name of the syscall that failed."`
	Errno    int32  `jsonschema:"The raw error code (errno) returned."`
	Error    string `jsonschema:"String representation of the error."`
}

type ExecuteSeedResult struct {
	ExecutionCachedID string      `jsonschema:"Cached ID. Pass to coverage tools to explore executed code."`
	CallErrors        []CallError `jsonschema:"List of calls that failed. Empty if all succeeded."`
}

func executeSeed(ctx *aflow.Context, state reproduceState, args ExecuteSeedArgs) (ExecuteSeedResult, error) {
	baseSeed := syzlang.BaseTestSeed{Path: args.BaseTestSeed}
	if err := baseSeed.Load(state.Syzkaller, state.TargetOS); err != nil {
		return ExecuteSeedResult{}, aflow.BadCallError("failed to read BaseTestSeed: %v", err)
	}

	fullSyz, baseLines := syzlang.CombineSyzPrograms(baseSeed.Data, args.ReproSyz)

	if fullSyz == "" {
		return ExecuteSeedResult{}, aflow.BadCallError("syz program cannot be empty")
	}

	pt, err := prog.GetTarget(targets.Linux, state.TargetArch)
	if err != nil {
		return ExecuteSeedResult{}, err
	}
	p, err := pt.Deserialize([]byte(fullSyz), prog.Strict)
	if err != nil {
		return ExecuteSeedResult{}, formatDeserializeError(err, baseLines)
	}
	if len(p.Calls) > 64 {
		return ExecuteSeedResult{}, aflow.BadCallError("program has %d calls, exceeding the limit of 64", len(p.Calls))
	}

	if state.Image == "" || state.VM == nil {
		// VM configuration is missing, we can only verify the program compiles.
		return ExecuteSeedResult{}, nil
	}

	executeArgs := state.toExecuteSeedArgs(baseSeed, args.ReproSyz)

	executionCachedID, err := crash.ExecuteSeedFunc(ctx, executeArgs)
	if err != nil {
		if aflow.IsFlowError(err) {
			return ExecuteSeedResult{}, err
		}
		return ExecuteSeedResult{}, aflow.BadCallError("%v", err)
	}

	callErrors, err := crash.LoadCallErrors(ctx, executionCachedID)
	if err != nil {
		return ExecuteSeedResult{}, err
	}
	baseCallsCount, err := syzlang.BaseSeedCallCount([]byte(baseSeed.Data), state.TargetArch)
	if err != nil {
		return ExecuteSeedResult{}, aflow.BadCallError("failed to get base test seed calls: %v", err)
	}

	var structuredErrors []CallError
	for i, errCode := range callErrors {
		if errCode != 0 {
			if i < baseCallsCount {
				return ExecuteSeedResult{}, aflow.BadCallError(
					"base test seed failed at syscall index %d with errno %d (%s). "+
						"This usually indicates an environment setup failure, the target is likely unreachable "+
						"with this base seed.", i, errCode, syscall.Errno(errCode).Error())
			}

			callName := "unknown"
			if i < len(p.Calls) {
				callName = p.Calls[i].Meta.Name
			}
			structuredErrors = append(structuredErrors, CallError{
				Index:    i - baseCallsCount,
				CallName: callName,
				Errno:    errCode,
				Error:    syscall.Errno(errCode).Error(),
			})
		}
	}

	return ExecuteSeedResult{
		ExecutionCachedID: executionCachedID,
		CallErrors:        structuredErrors,
	}, nil
}

type GetExecutedProgramArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID of the execution."`
}

type GetExecutedProgramResult struct {
	BaseTestSeed string `jsonschema:"Path to the base test seed, if any."`
	SyzProgram   string `jsonschema:"The generated syzlang program."`
}

func getExecutedProgram(ctx *aflow.Context, state reproduceState,
	args GetExecutedProgramArgs) (GetExecutedProgramResult, error) {
	if args.ExecutionCachedID == "" {
		return GetExecutedProgramResult{}, aflow.BadCallError("ExecutionCachedID is required")
	}
	baseSeed, generated, err := crash.LoadSeedProgramDetails(ctx, args.ExecutionCachedID)
	if err != nil {
		return GetExecutedProgramResult{}, aflow.BadCallError("failed to load program details: %v", err)
	}
	return GetExecutedProgramResult{
		BaseTestSeed: baseSeed,
		SyzProgram:   generated,
	}, nil
}

const deserializationErrorHelp = `

Syzlang Syntax Reminders:
- Multi-line statements are not supported. Each syscall must be on a single line.
- Inline comments (inside syscalls) are not supported. Put comments on their own lines.
- Double quotes ("...") are only for hex sequences. Use single quotes ('...') for strings and paths.`

// formatDeserializeError adjusts the line numbers in the deserialization error message
// if a base test seed was prepended, and appends a standard cheat sheet of syzlang syntax
// constraints to help LLM agents recover from syntax errors.
func formatDeserializeError(err error, baseLines int) error {
	errStr := err.Error()
	if baseLines > 0 {
		re := regexp.MustCompile(`(?m)line #(\d+):`)
		errStr = re.ReplaceAllStringFunc(errStr, func(match string) string {
			parts := re.FindStringSubmatch(match)
			if len(parts) > 1 {
				if lineNum, err := strconv.Atoi(parts[1]); err == nil && lineNum > baseLines {
					return fmt.Sprintf("line #%d:", lineNum-baseLines)
				}
			}
			return match
		})
	}
	return aflow.BadCallError("%v%s", errStr, deserializationErrorHelp)
}
