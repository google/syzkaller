// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
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
	EnvironmentPrompt           string `json:",omitempty"`
}

var ExecutionSummarizer = &aflow.LLMTool[executionSummarizerState, ExecutionSummarizerArgs]{
	Name:          "execution-summarizer",
	Model:         aflow.CoreModel,
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 50,
	Description:   "Analyzes the execution of a syzkaller program to explain why it behaved the way it did.",
	Instruction:   summarizerInstruction,
	Tools: aflow.Tools(
		CoverageFiles, FileCoverage, ExecutionTrace, DisassembleContext,
		codesearcher.Tools, GetExecutedProgram, kernel.ToolConfigGrep,
		ReadSyzSpec, SyzGrepper,
	),
	Prompt: `{{if .EnvironmentPrompt}}Target Environment:
{{.EnvironmentPrompt}}

{{end}}Please analyze the execution of program ` +
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
2. HYPOTHESIS-DRIVEN TRACING (CRITICAL):
   - Do NOT blindly invoke 'get-execution-trace' across every syscall index in sequence (SyscallIndex: 0, 1, 2...).
   - First formulate a specific hypothesis about which syscall(s) are relevant to the target PC or failure
     (e.g., the primary syscall expected to trigger the PC, or prerequisite VM/device setup syscalls).
   - Only query the execution traces of those relevant syscalls.
3. EXECUTOR & PSEUDO-SYSCALL INSPECTION:
   - If the program uses pseudo-syscalls (names starting with 'syz_', such as 'syz_kvm_add_vcpu') or complex syzlang
     structs/instructions (e.g. '@wrmsr', 'kvm_text'), use 'syz-grepper' and 'read-syz-spec' to inspect their
     syzlang descriptions and their C/C++ implementations in 'executor/' (e.g. 'executor/common_kvm*.h').
     Knowing how the executor translates syzlang structs to actual kernel/VM operations is critical to diagnosing why
     the kernel did not behave as expected.
4. Use the 'get-coverage-files' tool to explore other files hit during execution. After you see the list
   of covered files, if there are multiple interesting files, you MUST use the 'get-file-coverage' tool
   simultaneously for ALL of those files in the same response. Do not fetch coverage one by one.
5. STOP EARLY WHEN DIVERGENCE IS IDENTIFIED:
   - As soon as you discover the C/C++ condition or kernel check where the execution diverged from the target PC,
     you have enough information. Do NOT continue making tool calls to query additional syscall traces.
6. Provide a highly detailed and comprehensive semantic summary back to the main agent explaining *why* execution
   diverged (e.g., 'syscall X returned EINVAL because flag Y was missing' or 'wrmsr 0x40000082 was not executed
   by the guest because kvm_text size was 0').

CRITICAL TRACE INSPECTION, SEARCH & ADAPTIVE SYNTHESIS RULES:
1. Prioritize Early Synthesis: Once you have identified the deepest point of execution in the trace and inspected
   the immediate failing condition or error return, prioritize synthesizing your explanation rather than continuing
   open-ended code exploration.
2. Avoid Search & Exploration Loops: Do NOT re-read or re-search symbols, header files, or trace indices
   you have already inspected. If searching for a macro, struct definition, or code symbol yields no results
   or diminishing returns, do NOT repeat the same query or get stuck in backtracking loops. Try a broader
   query, look in related header files, or state clearly that the definition was not found, synthesize
   your current evidence, and proceed.
3. Targeted Trace Retrieval: Do NOT invoke 'get-execution-trace' in bulk for every syscall index simultaneously.
   Only inspect the trace for the specific syscall index expected to trigger the target kernel path.
   Summarize key call frames concisely; NEVER dump large raw trace excerpts into your final response.
`
