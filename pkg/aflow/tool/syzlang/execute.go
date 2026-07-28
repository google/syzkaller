// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/flatrpc"
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
	ReproSyz string `jsonschema:"Syz program to execute."`
}

type CallError struct {
	Index    int    `jsonschema:"0-based index of the failed syscall."`
	CallName string `jsonschema:"Name of the syscall that failed."`
	Errno    int32  `jsonschema:"The raw error code (errno) returned."`
	Error    string `jsonschema:"String representation of the error."`
}

const maxConsoleOutputLines = 200

type ExecuteSeedResult struct {
	ExecutionCachedID string      `jsonschema:"Cached ID. Pass to coverage tools to explore executed code."`
	CallErrors        []CallError `jsonschema:"List of calls that failed. Empty if all succeeded."`
}

func executeSeed(ctx *aflow.Context, state reproduceState, args ExecuteSeedArgs) (ExecuteSeedResult, error) {
	if args.ReproSyz == "" {
		return ExecuteSeedResult{}, aflow.BadCallError("syz program cannot be empty")
	}

	pt, err := prog.GetTarget(targets.Linux, state.TargetArch)
	if err != nil {
		return ExecuteSeedResult{}, err
	}
	args.ReproSyz = syzspec.RestoreBlobs(args.ReproSyz)
	p, err := pt.Deserialize([]byte(args.ReproSyz), prog.Strict)
	if err != nil {
		return ExecuteSeedResult{}, formatDeserializeError(err, 0)
	}
	if len(p.Calls) > 64 {
		return ExecuteSeedResult{}, aflow.BadCallError("program has %d calls, exceeding the limit of 64", len(p.Calls))
	}

	if state.Image == "" || state.VM == nil {
		// VM configuration is missing, we can only verify the program compiles.
		return ExecuteSeedResult{}, nil
	}

	executeArgs := state.toExecuteSeedArgs(args.ReproSyz)

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

	structuredErrors, err := formatCallErrors(callErrors, 0, p.Calls)
	if err != nil {
		return ExecuteSeedResult{}, err
	}

	return ExecuteSeedResult{
		ExecutionCachedID: executionCachedID,
		CallErrors:        structuredErrors,
	}, nil
}

func truncateConsoleOutput(output string, maxLines int) string {
	lines := strings.Split(output, "\n")
	if len(lines) <= maxLines {
		return output
	}
	truncated := lines[len(lines)-maxLines:]
	banner := fmt.Sprintf("... [VM console output truncated, showing last %d of %d lines] ...\n", maxLines, len(lines))
	return banner + strings.Join(truncated, "\n")
}

func formatCallErrors(callErrors []crash.CallError, baseCallsCount int, calls []*prog.Call) ([]CallError, error) {
	var structuredErrors []CallError
	for i, callErr := range callErrors {
		if callErr.Errno != 0 || callErr.Flags&flatrpc.CallFlagFinished == 0 {
			callName := "unknown"
			if i < len(calls) {
				callName = calls[i].Meta.Name
			}

			var errStr string
			if callErr.Flags&flatrpc.CallFlagExecuted == 0 {
				errStr = "call unexecuted (executor halted on an earlier call)"
			} else if callErr.Flags&flatrpc.CallFlagFinished == 0 {
				errStr = "call execution timed out or hung"
			} else {
				errStr = syscall.Errno(callErr.Errno).Error()
			}

			structuredErrors = append(structuredErrors, CallError{
				Index:    i,
				CallName: callName,
				Errno:    callErr.Errno,
				Error:    errStr,
			})
		}
	}
	return structuredErrors, nil
}

type GetExecutedProgramArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID of the execution."`
}

type GetExecutedProgramResult struct {
	SyzProgram string `jsonschema:"The generated syzlang program."`
}

func getExecutedProgram(ctx *aflow.Context, state reproduceState,
	args GetExecutedProgramArgs) (GetExecutedProgramResult, error) {
	if args.ExecutionCachedID == "" {
		return GetExecutedProgramResult{}, aflow.BadCallError("ExecutionCachedID is required")
	}
	generated, err := crash.LoadSeedProgramDetails(ctx, args.ExecutionCachedID)
	if err != nil {
		return GetExecutedProgramResult{}, aflow.BadCallError("failed to load program details: %v", err)
	}
	return GetExecutedProgramResult{
		SyzProgram: generated,
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
	errStr := syzspec.ReplaceBlobs(err.Error())
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
