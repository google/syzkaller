// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
)

type CheckPCReachedArgs struct {
	ExecutionCachedID string `jsonschema:"The cached execution ID of the attempt."`
}

type CheckPCReachedResult struct {
	Reached bool `jsonschema:"True if the target PC was reached during execution."`
}

type checkPCState struct {
	PC string
}

var CheckPCReached = aflow.NewFuncTool[checkPCState, CheckPCReachedArgs, CheckPCReachedResult](
	"check-pc-reached",
	func(ctx *aflow.Context, state checkPCState, args CheckPCReachedArgs) (CheckPCReachedResult, error) {
		if state.PC == "" {
			return CheckPCReachedResult{}, fmt.Errorf("target PC not found in state")
		}
		pc, err := parseFlexPC(state.PC)
		if err != nil {
			return CheckPCReachedResult{}, fmt.Errorf("invalid PC in state: %w", err)
		}
		reached, err := crash.CheckPCInCoverage(ctx, args.ExecutionCachedID, pc)
		if err != nil {
			return CheckPCReachedResult{}, aflow.BadCallError("failed to check PC in coverage: %v", err)
		}
		return CheckPCReachedResult{Reached: reached}, nil
	},
	"Checks if the target PC was reached during the execution attempt.")
