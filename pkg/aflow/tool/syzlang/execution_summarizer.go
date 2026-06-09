// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzlang"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type SummarizerInputs struct {
	LastFailedExecutionCachedID string
	File                        string
	PC                          uint64
}

type SummarizerOutputs struct {
	LastFailureSummary string `jsonschema:"Detailed summary of execution divergence and all relevant info."`
}

type SummarizerContext struct {
	ExecutionSummaryContext string
}

var ActionPrepareSummarizer = aflow.NewFuncAction("prepare-summarizer",
	func(ctx *aflow.Context, args SummarizerInputs) (SummarizerContext, error) {
		stateMap := ctx.StateMap()
		b, _ := json.Marshal(stateMap)
		var state reproduceState
		json.Unmarshal(b, &state)

		coverage, err := crash.LoadCoverage(ctx, args.LastFailedExecutionCachedID)
		if err != nil {
			return SummarizerContext{}, err
		}

		baseSeedPath, generated, err := crash.LoadSeedProgramDetails(ctx, args.LastFailedExecutionCachedID)
		if err != nil {
			return SummarizerContext{}, fmt.Errorf("failed to load program for ExecutionCachedID: %w", err)
		}
		syzProgram := generated
		if baseSeedPath != "" {
			syzProgram = "// Base Test Seed: " + baseSeedPath + "\n" + generated
		}

		targetFile := args.File
		targetPC := "Unknown"
		if args.PC != 0 {
			targetPC = fmt.Sprintf("0x%x", args.PC)
		}

		baseSeed := syzlang.BaseTestSeed{Path: baseSeedPath}
		if err := baseSeed.Load(state.Syzkaller, state.TargetOS); err != nil {
			return SummarizerContext{}, fmt.Errorf("failed to load base test seed: %w", err)
		}

		baseCallsCount, err := syzlang.BaseSeedCallCount([]byte(baseSeed.Data), state.TargetArch)
		if err != nil {
			return SummarizerContext{}, fmt.Errorf("failed to get base test seed calls: %w", err)
		}

		var traceBuilder strings.Builder
		traceBuilder.WriteString("Execution Trace (All Syscalls):\n")
		for i := range coverage {
			if i < baseCallsCount {
				continue
			}
			tr := processSyscallTrace(i, coverage[i], ExecutionTraceArgs{IncludeNoise: false})
			traceBuilder.WriteString(fmt.Sprintf("Syscall %d:\n", tr.CallIndex-baseCallsCount))
			for _, frame := range tr.Trace {
				traceBuilder.WriteString(fmt.Sprintf("  %s\n", frame))
			}
			traceBuilder.WriteString("\n")
		}

		covStr := "No target file provided."
		if targetFile != "" {
			covRes, err := getFileCoverage(ctx, state, FileCoverageArgs{
				ExecutionCachedID: args.LastFailedExecutionCachedID,
				Filename:          targetFile,
			})
			if err == nil {
				covStr = strings.Join(covRes.Snippets, "\n")
			} else {
				covStr = fmt.Sprintf("Failed to get coverage for %s: %v", targetFile, err)
			}
		}

		contextStr := fmt.Sprintf(`Target Execution Details:
- ExecutionCachedID: %s
- Target PC: %s

Syzlang Program:
%s

%s
Coverage for Target File (%s):
%s

Question from Parent Agent:
Why did this program fail to reach the target PC?`, args.LastFailedExecutionCachedID, targetPC, syzProgram,
			traceBuilder.String(), targetFile, covStr)

		return SummarizerContext{ExecutionSummaryContext: contextStr}, nil
	})

var SummarizerAgent = &aflow.LLMAgent{
	Name:     "execution-summarizer",
	Model:    aflow.GoodBalancedModel,
	TaskType: aflow.FormalReasoningTask,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs SummarizerOutputs) (SummarizerOutputs, error) {
			return outputs, nil
		}),
	Instruction: summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace, DisassembleContext, codesearcher.Tools,
	),
	Prompt: `{{.ExecutionSummaryContext}}`,
}

const summarizerInstruction = `
You are an expert in analyzing kernel executions. Your task is to comprehensively analyze the execution of a syzkaller
program, identifying the deepest point of execution before divergence and explaining why it diverged.
You must base all your claims on the provided execution trace and coverage information.
If you don't have enough information, you MUST state that instead of guessing.

The main agent has provided you with:
1. The target constraint (e.g., target file, and PC address).
2. The full syzkaller program that was executed.
3. The formatted execution traces for all syscalls.
4. The source code coverage snippets for the target file.

Instructions:
1. Review the initial Execution Trace and File Coverage provided by the main agent. The initial
   trace might be truncated if it is too long.
2. If the trace is truncated, use the 'get-execution-trace' tool with the 'Offset' and 'Limit'
   arguments to paginate through the omitted middle sections of the trace.
3. Use the 'get-coverage-files' tool to explore other files hit during execution. After you see the list
   of covered files, if there are multiple interesting files, you MUST use the 'get-file-coverage' tool
   simultaneously for ALL of those files in the same response. Do not fetch coverage one by one.
4. Find the deepest point or the exact divergence point in the trace.
5. Provide a highly detailed and comprehensive summary back to the main agent.

CRITICAL: You MUST reason about *why* the execution diverged and provide a high-level, semantic 
summary of the failure (e.g., 'syscall X returned EINVAL because flag Y was missing'). You MUST 
include ALL possible information relevant to the divergence, such as variable values, error codes, 
and control flow conditions, so the manager can fully understand the failure context and adjust 
its strategy. Do not focus excessively on low-level syntax.
`
