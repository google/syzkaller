// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/csource"
)

type ReproCInputs struct {
	BugDescription string

	KernelRepo   string
	KernelCommit string
	KernelConfig string

	Image     string
	Type      string
	VM        json.RawMessage
	Syzkaller string
}

type FormatCArgs struct {
	CandidateReproC string
}

type FormatCResult struct {
	FormattedReproC string
}

func FormatCFunc(ctx *aflow.Context, args FormatCArgs) (FormatCResult, error) {
	formatted, err := csource.Format([]byte(args.CandidateReproC))
	if err != nil {
		return FormatCResult{FormattedReproC: args.CandidateReproC}, nil
	}
	return FormatCResult{FormattedReproC: string(formatted)}, nil
}

var FormatC = aflow.NewFuncAction("format-c", FormatCFunc)

type TruncateLogArgs struct {
	ConsoleOutput        string
	CandidateCrashReport string
}

type TruncateLogResult struct {
	TruncatedConsoleOutput string
	TruncatedCrashReport   string
}

func TruncateLogFunc(ctx *aflow.Context, args TruncateLogArgs) (TruncateLogResult, error) {
	lines := strings.Split(args.ConsoleOutput, "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	return TruncateLogResult{
		TruncatedConsoleOutput: strings.Join(lines, "\n"),
		TruncatedCrashReport:   args.CandidateCrashReport,
	}, nil
}

var TruncateLog = aflow.NewFuncAction("truncate-log", TruncateLogFunc)

type OracleResult struct {
	Feedback       string `jsonschema:"Detailed feedback on the reproduction attempt"`
	ShouldContinue bool   `jsonschema:"Whether to continue the reproduction loop"`
	TitleMatches   bool   `jsonschema:"Whether the candidate crash title matches the expected bug"`
}

type LoopControllerArgs struct {
	Feedback             string
	ShouldContinue       bool
	TitleMatches         bool
	CandidateReproduced  bool
	CandidateReproC      string
	CandidateBugTitle    string
	CandidateCrashReport string
}

type LoopControllerResult struct {
	ContinueSignal        string
	ReproC                string
	OracleFeedback        string
	Reproduced            bool
	ReproducedBugTitle    string
	ReproducedCrashReport string
}

func LoopControllerFunc(ctx *aflow.Context, args LoopControllerArgs) (LoopControllerResult, error) {
	res := LoopControllerResult{
		OracleFeedback: args.Feedback,
	}

	shouldContinue := args.ShouldContinue

	if args.CandidateReproduced && args.TitleMatches {
		res.ReproC = args.CandidateReproC
		res.Reproduced = true
		res.ReproducedBugTitle = args.CandidateBugTitle
		res.ReproducedCrashReport = args.CandidateCrashReport
		shouldContinue = false
	} else if args.CandidateReproduced && !args.TitleMatches {
		shouldContinue = true
		res.OracleFeedback = fmt.Sprintf(
			"Collision detected: candidate reproducer triggered a crash with title %q, "+
				"which does not match the expected bug.",
			args.CandidateBugTitle,
		)
	}

	if shouldContinue {
		res.ContinueSignal = "continue"
	} else {
		res.ContinueSignal = ""
	}

	return res, nil
}

var LoopController = aflow.NewFuncAction("loop-controller", LoopControllerFunc)

type MergeStrategyArgs struct {
	InitialReproStrategy string
	RefinedReproStrategy string
}

type MergeStrategyResult struct {
	CurrentReproStrategy string
}

func MergeStrategyFunc(ctx *aflow.Context, args MergeStrategyArgs) (MergeStrategyResult, error) {
	if args.RefinedReproStrategy != "" {
		return MergeStrategyResult{CurrentReproStrategy: args.RefinedReproStrategy}, nil
	}
	return MergeStrategyResult{CurrentReproStrategy: args.InitialReproStrategy}, nil
}

var MergeStrategy = aflow.NewFuncAction("merge-strategy", MergeStrategyFunc)

type SaveReproCArgs struct {
	Reproduced bool
	ReproC     string
}

type SaveReproCResult struct {
}

func SaveReproCFunc(ctx *aflow.Context, args SaveReproCArgs) (SaveReproCResult, error) {
	if !args.Reproduced || args.ReproC == "" {
		return SaveReproCResult{}, nil
	}

	path := filepath.Join(ctx.Workdir, "repro.c")
	err := os.WriteFile(path, []byte(args.ReproC), 0644)
	if err != nil {
		return SaveReproCResult{}, fmt.Errorf("failed to save repro.c: %w", err)
	}
	fmt.Printf("Saved reproducer to %s\n", path)
	return SaveReproCResult{}, nil
}

var SaveReproC = aflow.NewFuncAction("save-repro-c", SaveReproCFunc)

func init() {
	aflow.Register[ReproCInputs, ai.ReproCOutputs](
		ai.WorkflowReproC,
		"reproduce a kernel crash and generate a C reproducer",
		&aflow.Flow{

			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:        "initial-researcher",
					Model:       aflow.BestExpensiveModel,
					Reply:       "InitialReproStrategy",
					TaskType:    aflow.FormalReasoningTask,
					Instruction: initialResearcherInstruction,
					Prompt:      initialResearcherPrompt,
					Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
				},
				&aflow.DoWhile{
					MaxIterations: 5,
					While:         "ContinueSignal",
					Do: aflow.Pipeline(
						&aflow.If{
							Cond: "OracleFeedback",
							Do: &aflow.LLMAgent{
								Name:        "strategy-refiner",
								Model:       aflow.BestExpensiveModel,
								Reply:       "RefinedReproStrategy",
								TaskType:    aflow.FormalReasoningTask,
								Instruction: refinerInstruction,
								Prompt:      refinerPrompt,
								Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
							},
						},
						MergeStrategy,
						&aflow.LLMAgent{
							Name:        "repro-generator",
							Model:       aflow.BestExpensiveModel,
							Reply:       "CandidateReproC",
							TaskType:    aflow.FormalReasoningTask,
							Instruction: generatorInstruction,
							Prompt:      generatorPrompt,
							Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
						},
						FormatC,
						crash.RunCRepro,
						TruncateLog,
						&aflow.LLMAgent{
							Name:        "repro-oracle",
							Model:       aflow.BestExpensiveModel,
							Outputs:     aflow.LLMOutputs[OracleResult](),
							TaskType:    aflow.FormalReasoningTask,
							Instruction: oracleInstruction,
							Prompt:      oraclePrompt,
							Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
						},
						LoopController,
					),
				},
				SaveReproC,
			),
		},
	)
}

const initialResearcherInstruction = `You are an AI assistant part of the Syzkaller/Aflow automated bug patching system.
Your goal is to analyze a Linux kernel bug description and propose a strategy to reproduce it
with a minimal, standalone C program.
This is for the strictly defensive purpose of verifying a bugfix in an isolated environment.
Do NOT propose an exploit. Focus on minimal technical reproduction of the bug state.`
const initialResearcherPrompt = `Bug Description: {{.BugDescription}}`

const refinerInstruction = `You are an expert in Linux kernel debugging.
Refine the reproduction strategy based on feedback from previous attempts.`
const refinerPrompt = `Bug Description: {{.BugDescription}}
Current Strategy: {{.CurrentReproStrategy}}
Feedback: {{.OracleFeedback}}`

const generatorInstruction = `You are an AI assistant part of the Syzkaller/Aflow automated bug patching system.
Your goal is to generate a minimal, standalone C program to REPRODUCE a specific kernel bug
for the purpose of VERIFYING a bugfix.
This is a strictly defensive task. The code will be run in an isolated QEMU virtual machine
to check if the bug is triggered or not.
Do NOT generate an exploit or weaponized code. Generate only the minimal code needed to trigger
the specific crash or condition described, to help developers confirm the bug and its fix.
Focus on the technical reproduction of the state, not on weaponization or payload delivery.
Print only the C program that could be executed directly, without backticks.`
const generatorPrompt = `Bug Description: {{.BugDescription}}
Strategy: {{.CurrentReproStrategy}}`

const oracleInstruction = `You are an AI assistant part of the Syzkaller/Aflow automated bug patching system.
Analyze the results of running the reproducer and determine if it was successful.
When Reproduced is false, analyze TruncatedConsoleOutput for execution patterns
(hangs, immediate exits, syscall failures)
to provide detailed feedback on why it failed and how to fix it.`
const oraclePrompt = `Bug Description: {{.BugDescription}}
Reproduced: {{.Reproduced}}
Console Output: {{.TruncatedConsoleOutput}}
Crash Report: {{.TruncatedCrashReport}}`
