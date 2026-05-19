// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/toolkit"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
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
	StraceBin string
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

type CompileCProgArgs struct {
	CurrentCandidateReproC string
}

type CompileCProgResult struct {
	CompilerError   string
	FormattedReproC string
}

func extractCCode(text string) string {
	re := regexp.MustCompile("(?s)```c\n(.*?)```")
	match := re.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	re = regexp.MustCompile("(?s)```\n(.*?)```")
	match = re.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	return text
}

func CompileCProgFunc(ctx *aflow.Context, args CompileCProgArgs) (CompileCProgResult, error) {
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return CompileCProgResult{}, err
	}
	currentC := extractCCode(args.CurrentCandidateReproC)
	expanded := strings.ReplaceAll(currentC, raceToolkitInclude, toolkit.GetRaceToolkit())
	formatted := []byte(expanded)

	bin, err := csource.BuildNoWarn(target, formatted)
	if err == nil {
		os.Remove(bin)
		return CompileCProgResult{
			CompilerError:   "",
			FormattedReproC: string(formatted),
		}, nil
	}
	return CompileCProgResult{
		CompilerError:   err.Error(),
		FormattedReproC: "",
	}, nil
}

var CompileCProg = aflow.NewFuncAction("compile-c-prog", CompileCProgFunc)

const raceToolkitInclude = `#include "race_toolkit.h"`

const repairerInstruction = `You are an experienced C developer.
Your goal is to repair a C program that failed to compile.
Analyze the compiler error and provide a corrected version of the C program.
Print only the C program that could be executed directly, without backticks.`

const repairerPrompt = `C Program:
{{.CurrentCandidateReproC}}

Compiler Error:
{{.CompilerError}}`

type MergeReproCArgs struct {
	RawCandidateReproC      string
	RepairedCandidateReproC string
}

type MergeReproCResult struct {
	CurrentCandidateReproC string
}

func MergeReproCFunc(ctx *aflow.Context, args MergeReproCArgs) (MergeReproCResult, error) {
	if args.RepairedCandidateReproC != "" {
		return MergeReproCResult{CurrentCandidateReproC: args.RepairedCandidateReproC}, nil
	}
	return MergeReproCResult{CurrentCandidateReproC: args.RawCandidateReproC}, nil
}

var MergeReproC = aflow.NewFuncAction("merge-repro-c", MergeReproCFunc)

type TruncateLogArgs struct {
	ConsoleOutput        string
	StraceOutput         string
	CandidateCrashReport string
}

type TruncateLogResult struct {
	TruncatedConsoleOutput string
	TruncatedStraceOutput  string
	TruncatedCrashReport   string
}

func TruncateLogFunc(ctx *aflow.Context, args TruncateLogArgs) (TruncateLogResult, error) {
	truncate := func(log string, limit int) string {
		lines := strings.Split(log, "\n")
		if len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}
		return strings.Join(lines, "\n")
	}

	const (
		defaultLogLimit = 200
		straceLogLimit  = 2000
	)

	return TruncateLogResult{
		TruncatedConsoleOutput: truncate(args.ConsoleOutput, defaultLogLimit),
		TruncatedStraceOutput:  truncate(args.StraceOutput, straceLogLimit),
		TruncatedCrashReport:   args.CandidateCrashReport,
	}, nil
}

var TruncateLog = aflow.NewFuncAction("truncate-log", TruncateLogFunc)

type OracleResult struct {
	Feedback     string `jsonschema:"Detailed feedback on the reproduction attempt"`
	TitleMatches bool   `jsonschema:"Whether the candidate crash title matches the expected bug"`
}

type GeneratorResult struct {
	RawCandidateReproC string `jsonschema:"The C reproducer code"`
}

type LoopControllerArgs struct {
	Feedback             string
	TitleMatches         bool
	CandidateReproduced  bool
	FormattedReproC      string
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

	if args.CandidateReproduced && args.TitleMatches {
		res.ReproC = args.FormattedReproC
		res.Reproduced = true
		res.ReproducedBugTitle = args.CandidateBugTitle
		res.ReproducedCrashReport = args.CandidateCrashReport
		res.ContinueSignal = ""
	} else {
		if args.CandidateReproduced && !args.TitleMatches {
			res.OracleFeedback = fmt.Sprintf(
				"Collision detected: candidate reproducer triggered a crash with title %q, "+
					"which does not match the expected bug.",
				args.CandidateBugTitle,
			)
		}
		res.ContinueSignal = "continue"
	}

	return res, nil
}

var LoopController = aflow.NewFuncAction("loop-controller", LoopControllerFunc)

type ExpandToolkitArgs struct {
	RawCandidateReproC string
}

type ExpandToolkitResult struct {
	CandidateReproC string
}

func ExpandToolkitFunc(ctx *aflow.Context, args ExpandToolkitArgs) (ExpandToolkitResult, error) {
	repro := strings.ReplaceAll(args.RawCandidateReproC, raceToolkitInclude, toolkit.GetRaceToolkit())
	return ExpandToolkitResult{CandidateReproC: repro}, nil
}

var ExpandToolkit = aflow.NewFuncAction("expand-toolkit", ExpandToolkitFunc)

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
	const compressTokensThreshold = 100000

	aflow.Register[ReproCInputs, ai.ReproCOutputs](
		ai.WorkflowReproC,
		"reproduce a kernel crash and generate a C reproducer",
		&aflow.Flow{
			Consts: map[string]any{
				"NeedStrace": true,
			},
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:           "initial-researcher",
					Model:          aflow.BestExpensiveModel,
					Reply:          "InitialReproStrategy",
					TaskType:       aflow.FormalReasoningTask,
					Instruction:    initialResearcherInstruction,
					Prompt:         initialResearcherPrompt,
					Tools:          aflow.Tools(codesearcher.Tools, grepper.Tool, toolkit.ToolGetToolkit),
					CompressTokens: compressTokensThreshold,
				},
				&aflow.DoWhile{
					MaxIterations: 20,
					While:         "ContinueSignal",
					Do: aflow.Pipeline(
						&aflow.If{
							Condition: "OracleFeedback",
							Do: &aflow.LLMAgent{
								Name:           "strategy-refiner",
								Model:          aflow.BestExpensiveModel,
								Reply:          "RefinedReproStrategy",
								TaskType:       aflow.FormalReasoningTask,
								Instruction:    refinerInstruction,
								Prompt:         refinerPrompt,
								Tools:          aflow.Tools(codesearcher.Tools, grepper.Tool, toolkit.ToolGetToolkit),
								CompressTokens: compressTokensThreshold,
							},
						},
						MergeStrategy,
						&aflow.LLMAgent{
							Name:           "repro-generator",
							Model:          aflow.BestExpensiveModel,
							Outputs:        aflow.LLMOutputs[GeneratorResult](),
							TaskType:       aflow.FormalReasoningTask,
							Instruction:    generatorInstruction,
							Prompt:         generatorPrompt,
							Tools:          aflow.Tools(codesearcher.Tools, grepper.Tool, toolkit.ToolGetToolkit),
							CompressTokens: compressTokensThreshold,
						},
						&aflow.DoWhile{
							MaxIterations: 3,
							While:         "CompilerError",
							Do: aflow.Pipeline(
								MergeReproC,
								CompileCProg,
								&aflow.If{
									Condition: "CompilerError",
									Do: &aflow.LLMAgent{
										Name:           "repro-repairer",
										Model:          aflow.BestExpensiveModel,
										Reply:          "RepairedCandidateReproC",
										TaskType:       aflow.FormalReasoningTask,
										Instruction:    repairerInstruction,
										Prompt:         repairerPrompt,
										Tools:          aflow.Tools(codesearcher.Tools, grepper.Tool, toolkit.ToolGetToolkit),
										CompressTokens: compressTokensThreshold,
									},
								},
							),
						},
						crash.RunCRepro,
						TruncateLog,
						&aflow.LLMAgent{
							Name:           "repro-oracle",
							Model:          aflow.BestExpensiveModel,
							Outputs:        aflow.LLMOutputs[OracleResult](),
							TaskType:       aflow.FormalReasoningTask,
							Instruction:    oracleInstruction,
							Prompt:         oraclePrompt,
							Tools:          aflow.Tools(codesearcher.Tools, grepper.Tool, toolkit.ToolGetToolkit),
							CompressTokens: compressTokensThreshold,
						},
						LoopController,
					),
				},
				SaveReproC,
			),
		},
	)
}

const initialResearcherInstruction = `You are a security researcher with deep Linux kernel background.
Your goal is to analyze a Linux kernel bug description and propose a strategy to reproduce it
with a minimal, standalone C program.
This is for the strictly defensive purpose of verifying a bugfix in an isolated environment.
Do NOT propose an exploit. Focus on minimal technical reproduction of the bug state.
Keep your analysis and strategy proposal concise. Do not write long explanations.`

const initialResearcherPrompt = `Bug Description: {{.BugDescription}}`

const refinerInstruction = `You are an expert in Linux kernel debugging.
Refine the reproduction strategy based on feedback from previous attempts.
Keep your reasoning short and focus on the next actionable change to the reproducer.
Do NOT repeat searches for the same symbols or files. Use the information you have already gathered.
If you are stuck, try a different approach or proceed to generate a candidate reproducer.`

const refinerPrompt = `Bug Description: {{.BugDescription}}
Current Strategy: {{.CurrentReproStrategy}}
Feedback: {{.OracleFeedback}}`

const generatorInstruction = `You are a security researcher with deep Linux kernel background.
Your goal is to generate a minimal, standalone C program to REPRODUCE a specific kernel bug
for the purpose of VERIFYING a bugfix.
This is a strictly defensive task. The code will be run in an isolated QEMU virtual machine
to check if the bug is triggered or not.
Do NOT generate an exploit or weaponized code. Generate only the minimal code needed to trigger
the specific crash or condition described, to help developers confirm the bug and its fix.
Focus on the technical reproduction of the state, not on weaponization or payload delivery.

Do not spend too much time analyzing or trying to generate a perfect one-shot reproducer.
Instead, follow an iterative approach: generate a simple candidate, execute it, analyze the results,
and improve it. Keep your reasoning steps short and focused on the next logical experiment.

To ensure that we can diagnose why a reproducer might fail to run on the test environment,
you MUST include detailed logging and error checking in the generated C program:
1. Use 'printf(...)' for all progress messages and error logs.
2. Every system call (e.g., socket, bind, listen, connect, ioctl, send) must check for a failure return value.
3. If a call fails, it must print a specific error message including the function name
and the error string (use strerror(errno)), and then exit with a non-zero status.
4. The program must print a message after every successful
major step in the reproduction sequence.
5. Generate code that follows this pattern for all operations:
    int res = do_something();
    if (res < 0) {
        printf("[-] Failed to do_something: %s\n", strerror(errno));
        exit(1);
    }
    printf("[+] do_something successful.\n");
6. For the very first attempt at generating a reproducer (when no previous feedback is provided),
prioritize generating a simple 'probe' program. This program's sole purpose is to verify that the
test environment has the necessary kernel capabilities. It should focus on probing the specific
kernel subsystems, device files, or syscalls required for the reproduction (for example: opening
/dev/vhci to check if the virtual Bluetooth controller is accessible, loading a minimal dummy BPF
program to check if BPF_SYSCALL is enabled and permitted, or making a specific socket/ioctl call
to verify subsystem availability). Print clear messages indicating success or failure of these
specific kernel/subsystem probes, and exit with 0 only if all relevant subsystem checks pass.
Do not attempt complex race conditions or heavy logic in this first version.`

const generatorPrompt = `Bug Description: {{.BugDescription}}
Strategy: {{.CurrentReproStrategy}}`

const oracleInstruction = `You are a security researcher with deep Linux kernel background.
Analyze the results of running the reproducer and determine if it was successful.
When Reproduced is false, analyze TruncatedConsoleOutput for execution patterns
(hangs, immediate exits, syscall failures)
to provide detailed feedback on why it failed and how to fix it.

The Strace Output will contain the syscall trace if the run was successful and strace was supported.
Use this trace to identify which syscall failed or behaved unexpectedly.

If the output indicates that this was a successful probe execution (all probes passed),
set Reproduced to false but provide feedback indicating that the environment is ready
and the agent should now proceed to generate the full reproducer in the next iteration.

If reproduction failed due to environmental issues (e.g., missing permissions, missing devices,
or sandbox restrictions), assume execution might succeed with a different approach or more
robust code (e.g., adding namespace setup or better error handling), and suggest modifications
to the C code.`

const oraclePrompt = `Bug Description: {{.BugDescription}}
Reproduced: {{.Reproduced}}
Console Output: {{.TruncatedConsoleOutput}}
Strace Output: {{.TruncatedStraceOutput}}
Crash Report: {{.TruncatedCrashReport}}
{{if .OtherCrashReports}}
Other crashes triggered:
{{range .OtherCrashReports}}
{{.}}
{{end}}
{{end}}
{{if .TestError}}Boot/Compilation Error: {{.TestError}}{{end}}`
