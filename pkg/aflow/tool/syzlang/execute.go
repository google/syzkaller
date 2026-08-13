// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
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

type ExecuteSeedResult struct {
	ExecutionCachedID string            `jsonschema:"Cached ID. Pass to coverage tools to explore executed code."`
	CallErrors        []crash.CallError `jsonschema:"List of calls that failed. Empty if all succeeded."`
}

func executeSeed(ctx *aflow.Context, state reproduceState, args ExecuteSeedArgs) (ExecuteSeedResult, error) {
	if args.ReproSyz == "" {
		return ExecuteSeedResult{}, aflow.BadCallError("syz program cannot be empty")
	}

	executeArgs := crash.ExecuteSeedArgs{
		TargetConfig: state.targetConfig(""),
		ReproSyz:     args.ReproSyz,
	}
	executionCachedID, err := crash.ExecuteSeedFunc(ctx, executeArgs)
	if err != nil {
		return ExecuteSeedResult{}, err
	}

	callErrors, err := crash.LoadCallErrors(ctx, executionCachedID)
	if err != nil {
		return ExecuteSeedResult{}, err
	}

	return ExecuteSeedResult{
		ExecutionCachedID: executionCachedID,
		CallErrors:        callErrors,
	}, nil
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
