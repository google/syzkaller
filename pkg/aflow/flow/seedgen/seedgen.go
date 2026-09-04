// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package seedgen implements the AI-guided seed generation workflow.
package seedgen

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

func seedGenPipeline(prefix ...aflow.Action) aflow.Action {
	steps := append([]aflow.Action{actionsyzlang.PrepareSyzFS}, prefix...)
	steps = append(steps,
		kernel.SymbolizePC,
		actionsyzlang.ActionExecuteCorpus,
		codesearcher.PrepareIndex,
		codesearcher.ActionExtractFunction,
		&aflow.DoWhile{
			While:         "ContinueLoop",
			MaxIterations: 5,
			Do: aflow.Pipeline(
				ActionPrepareFailedDetails,
				GeneratorAgent,
				&aflow.If{
					Condition: "JudgeStopped",
					Do: aflow.Pipeline(
						ActionFormatFailedHistory,
						HistorySummarizerAgent,
					),
				},
				ActionVerifyPCAndLoopState,
			),
		},
		ActionFormatOutput,
	)
	return aflow.Pipeline(steps...)
}

func init() {
	aflow.Register[ai.SeedGenArgs, ai.SeedGenOutputs](
		ai.WorkflowSeedGen,
		"generate a syzlang program to reach a specific code position",
		&aflow.Flow{
			Consts: map[string]any{
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"DocPseudoSyscalls":            docs.PseudoSyscalls,
				"DocSyzOS":                     docs.SyzOS,
			},
			Root: seedGenPipeline(
				ActionParsePC,
				kernel.Checkout,
				kernel.Build,
				crash.ActionConfigureRunner,
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
			generated, err := crash.LoadSeedProgramDetails(ctx, args.ExecutionCachedID)
			if err != nil {
				return ai.SeedGenOutputs{}, aflow.BadCallError("failed to read program from cache: %v", err)
			}
			seedSyz = ctx.RestoreBlobs(generated)
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
	PCs []string
}

var ActionParsePC = aflow.NewFuncAction("parse-pc", parsePCAction)

func parsePCAction(ctx *aflow.Context, args ParsePCArgs) (ParsePCResult, error) {
	pc, err := parseFlexPC(args.RawPC)
	if err != nil {
		return ParsePCResult{}, err
	}
	hexPC := fmt.Sprintf("0x%x", pc)
	return ParsePCResult{PCs: []string{hexPC}}, nil
}

func parseFlexPC(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if pc, err := strconv.ParseUint(s, 0, 64); err == nil {
		return pc, nil
	}
	return strconv.ParseUint(s, 16, 64)
}

type VerifyPCAndLoopStateArgs struct {
	ExecutionCachedID           string
	LastFailedExecutionCachedID string
	GeneratorGiveUp             bool
	GeneratorReason             string
	JudgeStopped                bool
	JudgeReason                 string
	FailedHistorySummary        string
	FailedHistorySummaries      []string
	PCs                         []string
}

type VerifyPCAndLoopStateResult struct {
	ContinueLoop                string
	PCReached                   bool
	LastFailedExecutionCachedID string
	FailedHistorySummaries      []string
}

var ActionVerifyPCAndLoopState = aflow.NewFuncAction("seedgen-verify-pc-and-loop", verifyPCAndLoopStateAction)

func verifyPCAndLoopStateAction(ctx *aflow.Context, args VerifyPCAndLoopStateArgs) (VerifyPCAndLoopStateResult, error) {
	summaries := args.FailedHistorySummaries
	if args.JudgeStopped && args.FailedHistorySummary != "" {
		summaries = append(slices.Clone(summaries), args.FailedHistorySummary)
	}

	if args.JudgeStopped {
		return VerifyPCAndLoopStateResult{
			ContinueLoop:                "yes",
			PCReached:                   false,
			FailedHistorySummaries:      summaries,
			LastFailedExecutionCachedID: args.LastFailedExecutionCachedID,
		}, nil
	}
	if args.GeneratorGiveUp {
		return VerifyPCAndLoopStateResult{
			PCReached:              false,
			FailedHistorySummaries: summaries,
		}, nil
	}

	reached, err := crash.CheckHexPCsInCoverage(ctx, args.ExecutionCachedID, args.PCs...)
	if err != nil {
		return VerifyPCAndLoopStateResult{}, err
	}
	if reached {
		return VerifyPCAndLoopStateResult{
			PCReached:              true,
			FailedHistorySummaries: summaries,
		}, nil
	}
	return VerifyPCAndLoopStateResult{
		ContinueLoop:                "yes",
		PCReached:                   false,
		LastFailedExecutionCachedID: args.ExecutionCachedID,
		FailedHistorySummaries:      summaries,
	}, nil
}

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
