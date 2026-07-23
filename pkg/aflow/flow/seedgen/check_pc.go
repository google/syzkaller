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
	PC  string   `json:",omitempty"`
	PCs []string `json:",omitempty"`
}

var CheckPCReached = aflow.NewFuncTool[checkPCState, CheckPCReachedArgs, CheckPCReachedResult](
	"check-pc-reached",
	func(ctx *aflow.Context, state checkPCState, args CheckPCReachedArgs) (CheckPCReachedResult, error) {
		candidatePCs := state.PCs
		if len(candidatePCs) == 0 && state.PC != "" {
			candidatePCs = []string{state.PC}
		}
		if len(candidatePCs) == 0 {
			return CheckPCReachedResult{}, fmt.Errorf("no target PC(s) found in state")
		}

		for _, pcStr := range candidatePCs {
			targetPC, err := parseHexPC(pcStr)
			if err != nil {
				continue
			}
			reached, err := crash.CheckPCInCoverage(ctx, args.ExecutionCachedID, targetPC)
			if err != nil {
				continue
			}
			if reached {
				return CheckPCReachedResult{Reached: true}, nil
			}
		}

		return CheckPCReachedResult{Reached: false}, nil
	},
	"Checks if any of the target PCs were reached during the execution attempt.")
