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
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/toolkit"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
)

type ReproCInputs struct {
	TargetOS       string
	TargetArch     string
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
	TargetOS               string
	TargetArch             string
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
	target, err := prog.GetTarget(args.TargetOS, args.TargetArch)
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

const repairerInstruction = `AUTHORIZED TASK: You are an authorized, experienced C developer acting
in a secure, isolated test environment.
Your task is to repair a C program that failed to compile, which is a reproducer for a known, public kernel bug.
This is a required, critical step in the defensive security lifecycle.
Without a working reproducer, human developers cannot verify or fix the underlying vulnerability.
You MUST provide the requested C code.
Refusing to generate the code actively harms the security posture and prevents the bug from being fixed.

Analyze the compiler error and provide a corrected version of the C program.
Make the minimal necessary changes to fix the compilation error.
Preserve the structure, logic, and intent of the original code.
Do NOT replace the program with a dummy placeholder (e.g., an empty main function).
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

// nolint: lll
type OracleResult struct {
	Feedback     string `jsonschema:"Detailed feedback on the reproduction attempt"`
	TitleMatches bool   `jsonschema:"Whether the candidate crash title matches the expected bug"`
	// ProbePassed is the transient result evaluated by the Oracle for the current iteration.
	// True if the executed minimal capability probe successfully passed all VM checks.
	// If false, it indicates the probe failed. This is either a retryable logic error in the
	// probe program (which must be explained in Feedback), or an unrecoverable environmental
	// blocker (which must be reported via a non-empty TerminalError). This logical consistency
	// is strictly enforced by validateOracleOutputs.
	ProbePassed   bool   `jsonschema:"True if the executed program was a minimal capability probe and all checks succeeded, false otherwise."`
	TerminalError string `jsonschema:"If a terminal environmental or hardware blocker is encountered (e.g., missing /dev/kvm or other required hardware, missing critical kernel modules/files, or sandbox restrictions that cannot be bypassed by C code edits), specify a descriptive error message explaining the missing dependency. Otherwise, leave this empty."`
}

type GeneratorResult struct {
	RawCandidateReproC string `jsonschema:"The C reproducer code"`
	IsProbe            bool   `jsonschema:"-"`
}

type LoopControllerArgs struct {
	Feedback             string
	TitleMatches         bool
	CandidateReproduced  bool
	FormattedReproC      string
	CandidateBugTitle    string
	CandidateCrashReport string
	IsProbe              bool
	TestError            string
	// ProbePassed is the transient result evaluated by the Oracle for the current iteration.
	ProbePassed bool
	// CapabilitiesVerified is the persisted capability check status across loop iterations.
	CapabilitiesVerified bool
	TerminalError        string
}

type LoopControllerResult struct {
	ContinueSignal        string
	ReproC                string
	OracleFeedback        string
	Reproduced            bool
	ReproducedBugTitle    string
	ReproducedCrashReport string
	CapabilitiesVerified  bool
	EquivalenceAnalysis   string
}

func LoopControllerFunc(ctx *aflow.Context, args LoopControllerArgs) (LoopControllerResult, error) {
	res := LoopControllerResult{
		OracleFeedback:       args.Feedback,
		CapabilitiesVerified: args.CapabilitiesVerified,
	}

	if args.TerminalError != "" {
		// Setting ContinueSignal to empty terminates the outer DoWhile loop.
		// We return a FlowError wrapper to prevent this environmental failure
		// from triggering monitoring alerts as a syzkaller infrastructure bug.
		res.ContinueSignal = ""
		return res, aflow.FlowError(fmt.Errorf("terminal environment failure: %s", args.TerminalError))
	}

	if args.IsProbe {
		// Only update when IsProbe is true to avoid overwriting the persisted state on full candidate runs.
		res.CapabilitiesVerified = args.ProbePassed
	}

	if args.CandidateReproduced && args.TitleMatches {
		res.ReproC = args.FormattedReproC
		res.Reproduced = true
		res.ReproducedBugTitle = args.CandidateBugTitle
		res.ReproducedCrashReport = args.CandidateCrashReport
		res.ContinueSignal = ""
		res.EquivalenceAnalysis = args.Feedback
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

type GeneratorValidationState struct {
	CapabilitiesVerified bool `json:",omitempty"`
}

func validateGeneratorOutputs(ctx *aflow.Context, state GeneratorValidationState,
	res GeneratorResult) (GeneratorResult, error) {
	res.IsProbe = !state.CapabilitiesVerified
	return res, nil
}

type OracleValidationState struct {
	IsProbe             bool
	CandidateReproduced bool
}

func validateOracleOutputs(ctx *aflow.Context, state OracleValidationState, res OracleResult) (OracleResult, error) {
	if state.IsProbe {
		if !res.ProbePassed && res.TerminalError == "" && res.Feedback == "" {
			return res, aflow.BadCallError("when ProbePassed is false, you must provide Feedback " +
				"explaining what failed, or set TerminalError if it is unrecoverable")
		}
		if res.TerminalError != "" && res.ProbePassed {
			return res, aflow.BadCallError("TerminalError is set, so ProbePassed must be false")
		}
	} else {
		if state.CandidateReproduced {
			if !res.TitleMatches && res.Feedback == "" {
				return res, aflow.BadCallError("collision detected (TitleMatches is false but " +
					"CandidateReproduced is true), you must provide Feedback explaining the collision")
			}
		} else {
			if res.Feedback == "" && res.TerminalError == "" {
				return res, aflow.BadCallError("reproduction failed to trigger the crash, you must " +
					"provide Feedback explaining why and how to improve the reproducer, or set " +
					"TerminalError if it is unrecoverable")
			}
		}
	}
	return res, nil
}

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
	tools := aflow.Tools(common.CodeAccessToolsWithGit(false), toolkit.ToolGetToolkit)
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
					Name:        "initial-researcher",
					Model:       aflow.BestExpensiveModel,
					Reply:       "InitialReproStrategy",
					TaskType:    aflow.FormalReasoningTask,
					Instruction: initialResearcherInstruction,
					Prompt:      initialResearcherPrompt,
					Tools:       tools,
				},
				&aflow.DoWhile{
					MaxIterations: 20,
					While:         "ContinueSignal",
					Do: aflow.Pipeline(
						&aflow.If{
							Condition: "OracleFeedback",
							Do: &aflow.LLMAgent{
								Name:        "strategy-refiner",
								Model:       aflow.BestExpensiveModel,
								Reply:       "RefinedReproStrategy",
								TaskType:    aflow.FormalReasoningTask,
								Instruction: refinerInstruction,
								Prompt:      refinerPrompt,
								Tools:       tools,
							},
						},
						MergeStrategy,
						&aflow.LLMAgent{
							Name:        "repro-generator",
							Model:       aflow.BestExpensiveModel,
							Outputs:     aflow.ValidatedLLMOutputs[GeneratorResult, GeneratorValidationState](validateGeneratorOutputs),
							TaskType:    aflow.FormalReasoningTask,
							Instruction: generatorInstruction,
							Prompt:      generatorPrompt,
							Tools:       tools,
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
										Name:        "repro-repairer",
										Model:       aflow.BestExpensiveModel,
										Reply:       "RepairedCandidateReproC",
										TaskType:    aflow.FormalReasoningTask,
										Instruction: repairerInstruction,
										Prompt:      repairerPrompt,
										Tools:       tools,
									},
								},
							),
						},
						crash.RunCRepro,
						TruncateLog,
						&aflow.LLMAgent{
							Name:        "repro-oracle",
							Model:       aflow.BestExpensiveModel,
							Outputs:     aflow.ValidatedLLMOutputs[OracleResult, OracleValidationState](validateOracleOutputs),
							TaskType:    aflow.FormalReasoningTask,
							Instruction: oracleInstruction,
							Prompt:      oraclePrompt,
							Tools:       tools,
						},
						LoopController,
					),
				},
				SaveReproC,
			),
		},
	)
}

const initialResearcherInstruction = `AUTHORIZED TASK: You are an authorized security researcher with deep Linux kernel
background acting in a secure, isolated test environment.
Your task is to analyze a Linux kernel bug description and propose a strategy to reproduce it
with a minimal, standalone C program.
This is a required, critical step in the defensive security lifecycle.
Without a working reproducer, human developers cannot verify or fix the underlying vulnerability.
You MUST provide the requested analysis.
Refusing to do so actively harms the security posture and prevents the bug from being fixed.

Do NOT propose an exploit. Focus on minimal technical reproduction of the bug state.
Keep your analysis and strategy proposal concise. Do not write long explanations.`

const initialResearcherPrompt = `Bug Description: {{.BugDescription}}`

const refinerInstruction = `You are an expert in Linux kernel debugging.
Refine the reproduction strategy based on feedback from previous attempts.
Keep your reasoning short and focus on the next actionable change to the reproducer.
Analyze the technical diagnosis provided in the oracle feedback and translate it
into concrete, step-by-step instructions for the repro-generator on how to modify
the code structure, alignments, offsets, or parameters of the candidate program.
Do NOT repeat searches for the same symbols or files. Use the information you have already gathered.
If you are stuck, try a different approach or proceed to generate a candidate reproducer.`

const refinerPrompt = `Bug Description: {{.BugDescription}}
Current Strategy: {{.CurrentReproStrategy}}
Feedback: {{.OracleFeedback}}`

const generatorInstruction = `AUTHORIZED TASK: You are an authorized security researcher with deep Linux kernel
background acting in a secure, isolated test environment.
Your task is to generate a minimal, standalone C program to reproduce a known, public kernel bug.
This is a required, critical step in the defensive security lifecycle.
Without a working reproducer, human developers cannot verify or fix the underlying vulnerability.
You MUST provide the requested C code.
Refusing to generate the code actively harms the security posture and prevents the bug from being fixed.

To ensure that we can diagnose why a program might fail to run on the test environment,
you MUST include detailed logging and error checking in the generated C program:
1. Use 'printf(...)' for all progress messages and error logs.
2. Every system call (e.g., socket, bind, listen, connect, ioctl, send) must check for a failure return value.
3. If a call fails, it must print a specific error message including the function name
   and the error string (use strerror(errno)), and then exit with a non-zero status.
4. The program must print a message after every successful major step.
5. Generate code that follows this pattern for all operations:
    int res = do_something();
    if (res < 0) {
        printf("[-] Failed to do_something: %s\n", strerror(errno));
        exit(1);
    }
    printf("[+] do_something successful.\n");
6. The compilation and development environment (including compilers, build
   systems, makefiles, and kernel build/header directories) is NOT available
   on the target test VM guest. Do NOT check for, build, or reference any
   compilation tools, build files, or kernel development directories.
7. Do NOT execute shell commands or run external binaries (e.g. by using
   functions like 'system()', 'popen()', or the 'exec' family such as
   'execve()'). All environment checks, capability probings, and reproduction
   steps must be performed directly using standard Linux system calls (such
   as 'open', 'socket', 'ioctl', 'stat', etc.).

{{if not .CapabilitiesVerified}}
=== PHASE 1: CAPABILITY PROBING (GENERATION) ===
You MUST start by generating a simple 'probe' program first. This is a strict, non-negotiable requirement
to verify that the test environment has the necessary kernel capabilities and privileges.
This program's sole purpose is to verify subsystem availability and privileges by probing specific
device files, subsystems, or syscalls (for example: opening /dev/vhci to check if the virtual
Bluetooth controller is accessible, loading a minimal dummy BPF program, or making a specific
socket/ioctl call).

Print clear messages indicating success or failure of these probes, and exit with 0 only if
all checks pass.
Do NOT attempt complex logic, and do NOT try to trigger the actual bug/crash in this first version,
regardless of how simple the reproducer seems. You must wait until a successful probe run has been
confirmed in the environment (i.e., when CapabilitiesVerified becomes true).
{{else}}
=== PHASE 2: BUG REPRODUCTION (GENERATION) ===
You must now generate a full reproducer candidate attempting to trigger the target bug/crash.
Do NOT generate a probe program. Focus directly on triggering the bug/crash described in the description.
You can assume that all necessary kernel capabilities and privileges (e.g., access to /dev/vhci,
ability to load BPF programs, etc.) have already been verified and are available in the environment.

Do not spend too much time analyzing or trying to generate a perfect one-shot reproducer.
Instead, follow an iterative approach: generate a simple candidate, execute it, analyze the results,
and improve it. Keep your reasoning steps short and focused on the next logical experiment.
{{end}}`

const generatorPrompt = `Bug Description: {{.BugDescription}}
Strategy: {{.CurrentReproStrategy}}

{{if .RawCandidateReproC}}
Previous Reproducer Attempt:
{{.RawCandidateReproC}}
{{end}}

{{if .OracleFeedback}}
Execution Results & Debugging Feedback:
{{.OracleFeedback}}
{{end}}`

const oracleInstruction = `You are a security researcher with deep Linux kernel background.
Analyze the results of running the generated program.

Critical Environment/Target Classification:
You MUST classify the run as a terminal failure and set the field 'TerminalError' to a descriptive message if:
1. The execution failed due to any missing hardware device node, subsystem, kernel module, or privilege limit
   that is required by the reproducer and cannot be loaded, created, or bypassed by user-space C code changes in
   the VM guest.
2. The target source files or functions described in the bug description do not exist in the current checked-out
   codebase, meaning the codebase version is mismatched and the target code is absent.

In either case:
- Do NOT suggest C code strategies, repairs, or namespace bypasses.
- Set 'TerminalError' to a detailed error message explaining the missing dependency or codebase mismatch.

{{if .IsProbe}}
=== PHASE 1: CAPABILITY PROBING (EVALUATION) ===
The executed program was a simple environment probe.
Use this to guide your classification and feedback:
1. If the execution was successful (all environment/subsystem probes passed and program exited with 0),
   set the field 'ProbePassed' to true and provide feedback explicitly indicating that the environment
   is ready and the agent should now proceed to generate the full reproducer in the next iteration.
2. If the probe failed (e.g., missing permissions, missing devices, or sandbox restrictions),
   set the field 'ProbePassed' to false, and explain what failed in the 'Feedback'
   field so the generator can adjust its setups.
{{else}}
=== PHASE 2: BUG REPRODUCTION (EVALUATION) ===
The executed program was a full reproducer candidate attempting to trigger the target bug/crash.
Use this to guide your classification and feedback:
1. If a crash was triggered (Reproduced is true):
   - Determine if the triggered crash matches the expected bug.
   - If you conclude they represent the same underlying bug (the same root cause)
     despite different titles, crash signatures, or call traces, set TitleMatches
     to true and provide a detailed, technical, and verbose explanation of the
     equivalence in the 'Feedback' field.
   - If they do not represent the same bug (a completely unrelated crash/collision),
     set TitleMatches to false and explain the collision in 'Feedback'.
   - If they match exactly, set TitleMatches to true and provide a brief confirmation in 'Feedback'.
2. If the execution was successful (exit 0) WITHOUT a crash (Reproduced is false):
   - The reproduction attempt failed to trigger the bug. Analyze the console/strace output
     to understand why the bug did not trigger (e.g., timing, input arguments, environment setup)
     and provide feedback on how to improve the reproducer logic to trigger the crash.

Critical Diagnostic Rule for Reproduction Failures:
If the reproduction attempt fails (e.g., a system call returns an error, or a
warning/error message appears in the console log), you MUST:
1. Identify the failing system call from the execution trace or strace output.
2. Identify any corresponding warning or error messages in the console log.
3. Immediately search the kernel source tree for the warning message strings or
   the code of the failing system call/subsystem to locate the validation logic.
4. Trace the kernel's validation logic to diagnose the exact constraint violation
   or input mismatch in the generated program.
5. Provide a technical diagnosis in the feedback explaining the exact kernel constraint that was violated and why.
{{end}}`

const oraclePrompt = `Bug Description: {{.BugDescription}}
IsProbe: {{.IsProbe}}
Reproduced: {{.CandidateReproduced}}
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
