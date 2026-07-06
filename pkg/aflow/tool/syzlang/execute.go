// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"syscall"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
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
		return ExecuteSeedResult{}, aflow.BadCallError("%v", err)
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

	var structuredErrors []CallError
	for i, errCode := range callErrors {
		if errCode != 0 {
			callName := "unknown"
			if i < len(p.Calls) {
				callName = p.Calls[i].Meta.Name
			}
			structuredErrors = append(structuredErrors, CallError{
				Index:    i,
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

func GetTestSeed(file string) ([]byte, error) {
	return syzspec.NewSyzFS("", "linux").ReadFile(file)
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
