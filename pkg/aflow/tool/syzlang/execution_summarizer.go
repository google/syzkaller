// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type ExecutionSummarizerArgs struct {
	ExecutionCachedID string `jsonschema:"Optional cached execution ID (defaults to last failed)."`
	Question          string `jsonschema:"The question to answer about this execution."`
}

type executionSummarizerState struct {
	File                        string
	PC                          string
	PCs                         []string
	LastFailedExecutionCachedID string
}

var ExecutionSummarizer = &aflow.LLMTool[executionSummarizerState, ExecutionSummarizerArgs]{
	Name:        "execution-summarizer",
	Model:       aflow.GoodBalancedModel,
	TaskType:    aflow.FormalReasoningTask,
	Description: "Analyzes the execution of a syzkaller program to explain why it behaved the way it did.",
	Instruction: summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace, DisassembleContext,
		codesearcher.Tools, GetExecutedProgram, crash.GetEnvironment,
	),
	Prompt: `Please analyze the execution of program ` +
		`{{if .ExecutionCachedID}}{{.ExecutionCachedID}}{{else}}{{.LastFailedExecutionCachedID}}{{end}} ` +
		`to answer the question:
{{if .Question}}{{.Question}}{{else}}Why did this program fail to reach the target PC?{{end}}

Target file: {{.File}}
{{if .PCs}}Target PCs: {{range $i, $pc := .PCs}}{{if $i}}, {{end}}{{$pc}}{{end}}
{{else if .PC}}Target PC: {{.PC}}{{end}}`,
}

const summarizerInstruction = `
You are an expert in analyzing kernel executions. Your task is to comprehensively analyze the execution of a syzkaller
program, identifying the deepest point of execution before divergence and explaining why it diverged.
You must base all your claims on the execution trace, program details, and coverage information.
If you don't have enough information, you MUST state that instead of guessing.

CRITICAL CONSTRAINTS ON SPECULATION:
1. You MUST ONLY analyze the actual executed trace provided in ExecutionCachedID.
2. You MUST NEVER speculate about external agents (such as 'code-fixer'), previous program versions,
   or code lines that were omitted prior to execution.
3. If the executed program did not contain or execute a setup syscall for a target driver, simply state
   that the trace did not execute those calls and identify the deepest point reached by the executed trace.
   Do NOT attempt to guess why lines were deleted or modified before execution.

The main agent has provided you with:
1. The target constraint (e.g., target file, and PC address).
2. The ExecutionCachedID of the execution to analyze.

Instructions:
1. Use the 'get-executed-program' tool to load the syzlang program that was executed.
2. Use the 'get-execution-trace' tool to fetch the execution trace.
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

Avoid Search Loops: If you are searching for a macro, struct definition, or code symbol (using codesearch tools)
and the initial search returns no results, do NOT repeat the same query or get stuck in backtracking loops.
Try a broader search query, look in related header files, or state clearly that the definition was not found
and proceed with the remaining analysis.
`
