// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package seedgen implements the AI-guided seed generation workflow.
package seedgen

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	aflow_syzlang "github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type SeedGenInputs struct {
	RawPC        string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	Image        string
	Type         string
	VM           json.RawMessage
	Syzkaller    string
	TargetOS     string
	TargetArch   string
	Snapshot     bool
}

func init() {
	aflow.Register[SeedGenInputs, ai.SeedGenOutputs](
		ai.WorkflowSeedGen,
		"generate a syzlang program to reach a specific code position",
		&aflow.Flow{
			Consts: map[string]any{
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"DocPseudoSyscalls":            docs.PseudoSyscalls,
			},
			Root: aflow.Pipeline(
				actionsyzlang.PrepareSyzFS,
				ActionParsePC,
				kernel.Checkout,
				kernel.Build,
				crash.ActionConfigureRunner,
				kernel.SymbolizePC,
				codesearcher.PrepareIndex,
				codesearcher.ActionExtractFunction,
				codesearcher.ActionExtractIndirectCallers,
				&aflow.DoWhile{
					While:         "ContinueLoop",
					MaxIterations: 20,
					Do: aflow.Pipeline(
						&aflow.If{
							Condition: "LastFailedExecutionCachedID",
							Do: aflow.Pipeline(
								ActionPrepareFailedDetails,
								HistorySummarizerAgent,
							),
						},
						GeneratorAgent,
						ActionVerifyPCAndLoopState,
					),
				},
				ActionFormatOutput,
			),
		},
	)
}

type FormatOutputArgs struct {
	ExecutionCachedID string
	GeneratorGiveUp   bool
	GeneratorReason   string
	PCReached         bool
}

var ActionFormatOutput = aflow.NewFuncAction("format-output",
	func(ctx *aflow.Context, args FormatOutputArgs) (ai.SeedGenOutputs, error) {
		seedSyz := ""
		if args.ExecutionCachedID != "" {
			var err error
			generated, err := crash.LoadSeedProgramDetails(ctx, args.ExecutionCachedID)
			if err != nil {
				return ai.SeedGenOutputs{}, aflow.BadCallError("failed to read program from cache: %v", err)
			}
			seedSyz = aflow_syzlang.RestoreBlobs(generated)
		}

		return ai.SeedGenOutputs{
			SeedSyz: seedSyz,
			Success: args.PCReached,
			GiveUp:  args.GeneratorGiveUp,
			Reason:  args.GeneratorReason,
		}, nil
	})

type ParsePCArgs struct {
	RawPC string
}

type ParsePCResult struct {
	PC uint64
}

var ActionParsePC = aflow.NewFuncAction("parse-pc", parsePCAction)

func parsePCAction(ctx *aflow.Context, args ParsePCArgs) (ParsePCResult, error) {
	raw := strings.TrimSpace(args.RawPC)
	if strings.HasPrefix(raw, "0x") {
		pc, err := strconv.ParseUint(raw[2:], 16, 64)
		return ParsePCResult{PC: pc}, err
	}

	pc, err := strconv.ParseUint(raw, 0, 64)
	if err == nil {
		return ParsePCResult{PC: pc}, nil
	}

	pc, err = strconv.ParseUint(raw, 16, 64)
	return ParsePCResult{PC: pc}, err
}

type VerifyPCAndLoopStateArgs struct {
	ExecutionCachedID string
	GeneratorGiveUp   bool
	GeneratorReason   string
	PC                uint64
}

type VerifyPCAndLoopStateResult struct {
	ContinueLoop                string
	PCReached                   bool
	LastFailedExecutionCachedID string
	LastFailedHistorySummary    string
}

var ActionVerifyPCAndLoopState = aflow.NewFuncAction("seedgen-verify-pc-and-loop",
	func(ctx *aflow.Context, args VerifyPCAndLoopStateArgs) (VerifyPCAndLoopStateResult, error) {
		if args.GeneratorGiveUp {
			return VerifyPCAndLoopStateResult{ContinueLoop: "", PCReached: false}, nil
		}
		if args.ExecutionCachedID == "" {
			// This shouldn't happen due to GeneratorAgent output validation, but handle it safely.
			return VerifyPCAndLoopStateResult{ContinueLoop: "yes", PCReached: false}, nil
		}

		reached, err := crash.CheckPCInCoverage(ctx, args.ExecutionCachedID, args.PC)
		if err != nil {
			return VerifyPCAndLoopStateResult{}, err
		}

		if reached {
			return VerifyPCAndLoopStateResult{ContinueLoop: "", PCReached: true}, nil
		}
		res := VerifyPCAndLoopStateResult{
			ContinueLoop:                "yes",
			PCReached:                   false,
			LastFailedExecutionCachedID: args.ExecutionCachedID,
		}
		return res, nil
	})

type PrepareFailedDetailsArgs struct {
	LastFailedExecutionCachedID string
}

type PrepareFailedDetailsResult struct {
	LastFailedGeneratedSyz string
}

var ActionPrepareFailedDetails = aflow.NewFuncAction("seedgen-prepare-failed-details",
	func(ctx *aflow.Context, args PrepareFailedDetailsArgs) (PrepareFailedDetailsResult, error) {
		if args.LastFailedExecutionCachedID == "" {
			return PrepareFailedDetailsResult{}, nil
		}
		generated, err := crash.LoadSeedProgramDetails(ctx, args.LastFailedExecutionCachedID)
		return PrepareFailedDetailsResult{
			LastFailedGeneratedSyz: generated,
		}, err
	})
