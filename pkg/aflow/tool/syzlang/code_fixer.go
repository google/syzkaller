package syzlang

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

type CodeFixerArgs struct {
	BaseTestSeed     string `jsonschema:"Optional path to a test seed file. MUST be provided if requested by generator."`
	SyzProgram       string `jsonschema:"The syzlang program that needs debugging."`
	IgnoreCallErrors bool   `jsonschema:"Ignore syscall execution call errors if target is in an error path."`
}

type CodeFixerResult struct {
	ExecutionCachedID string `jsonschema:"Cached execution ID of the successful run."`
	Program           string `jsonschema:"Leave this empty. It will be replaced automatically."`
	BaseTestSeed      string `jsonschema:"Leave this empty. It will be replaced automatically."`
	ProgramDiff       string `jsonschema:"Leave this empty. It will be replaced automatically."`
}

func validateCodeFixerOutputs(
	ctx *aflow.Context, state struct{}, args CodeFixerArgs, res CodeFixerResult,
) (CodeFixerResult, error) {
	res.ExecutionCachedID = strings.TrimSpace(res.ExecutionCachedID)
	if res.ExecutionCachedID == "" {
		return res, aflow.BadCallError("returned ExecutionCachedID cannot be empty")
	}
	baseSeed, finalProg, err := crash.LoadSeedProgramDetails(ctx, res.ExecutionCachedID)
	if err != nil {
		return res, aflow.BadCallError("invalid ExecutionCachedID %q: %v. "+
			"You must return the ExecutionCachedID of a successful run.", res.ExecutionCachedID, err)
	}
	res.Program = finalProg
	res.BaseTestSeed = baseSeed
	res.ProgramDiff = diffPrograms(args.SyzProgram, finalProg)
	return res, nil
}

var CodeFixer = &aflow.StructuredLLMTool[struct{}, CodeFixerArgs, CodeFixerResult]{
	Name:     "code-fixer",
	Model:    aflow.Temporary35FlashOnlyModel,
	Outputs:  aflow.ValidatedLLMToolOutputs[CodeFixerResult, struct{}, CodeFixerArgs](validateCodeFixerOutputs),
	TaskType: aflow.FormalReasoningTask,
	Description: "A subagent tool that takes a syzlang program and repeatedly executes it " +
		"until it has no compilation or runtime call errors (e.g. EINVAL). " +
		"If IgnoreCallErrors is set to true, it will ignore execution call errors " +
		"and only fix compilation/syntax errors. Returns the ExecutionCachedID of the run.",
	Instruction: "You are an expert syzkaller seed debugger.\n" +
		"The parent Generator has provided an initial syzlang program to reach the target.\n" +
		"You may also be provided with a Base Test Seed path (e.g. test/vusb_cdc_ecm) which sets up the environment.\n" +
		"These test seeds are not for you to understand in detail, but only to set up some environment " +
		"like devices or file system.\n" +
		"Your job is ONLY to debug any syntax/compilation or call errors in the provided syzlang program.\n" +
		"Do NOT generate new logic to reach something or debug why something is not reached.\n" +
		"If the seed executes successfully (i.e. returns an ExecutionCachedID and " +
		"either CallErrors is empty or you are instructed to ignore call errors), " +
		"you MUST immediately yield by returning the ExecutionCachedID as your final reply. " +
		"It is NOT your job to reason or double check the program.\n" +
		"You MUST:\n" +
		"1. Execute the syzlang program using '{{.toolExecuteSeed}}'. IMPORTANT: You must pass the BaseTestSeed " +
		"to the tool if one was provided in your prompt.\n" +
		"   Any errors in the base test seed will be returned separately. Do NOT try to fix base test seed " +
		"errors, they indicate environment failures.\n" +
		"   The 'Index' of the CallErrors returned are 0-based and relative ONLY to the generated syzlang " +
		"program you are debugging.\n" +
		"2. If there are syntax errors or call errors (e.g. EFAULT, EINVAL), fix them\n" +
		"using '{{.toolReadSyzSpec}}' and '{{.toolSyzGrepper}}' to ensure arguments match expected descriptions.\n" +
		"3. Execute again until you get one successful execution " +
		"(i.e. no compiler errors, and also no call errors unless you are instructed to ignore them).\n" +
		"4. Provide the ExecutionCachedID as your final text reply.\n" +
		"Do NOT attempt to verify PC coverage or diagnose divergence. That will be handled by the pipeline.\n\n" +
		"CRITICAL SYZLANG CONSTRAINTS:\n" +
		"- Arrays vs Buffers: Array arguments MUST be formatted as `[val1, val2]` " +
		"while Buffer arguments MUST be formatted as strings (e.g. `\"\\x00\\x01\"` or `'string'`). " +
		"Do NOT use array syntax for buffers.\n" +
		"- Struct Fields: Structs MUST contain the exact number of fields specified in their definition. " +
		"Use `AUTO` if you want to omit fields or let the fuzzer fill them.\n" +
		"- String Formats: String arguments must be explicitly escaped or properly formatted according to the type.\n\n" +
		"===\n{{.DocProgramSyntax}}\n===\n\n" +
		"Document about syzlang system call descriptions syntax:\n" +
		"===\n{{.DocSyscallDescriptionsSyntax}}\n===\n\n" +
		"Document about pseudo-syscalls:\n" +
		"===\n{{.DocPseudoSyscalls}}\n===\n",
	Tools: aflow.Tools(
		ExecuteSeed,
		ReadSyzSpec,
		SyzGrepper,
	),
	Judge: &aflow.LLMJudge{
		Name:               "code-fixer-judge",
		Model:              aflow.Temporary35FlashOnlyModel,
		MinIterations:      30,
		EvaluationInterval: 10,
		Instruction: "You are a Judge Agent monitoring the execution of a subagent debugging a syzlang program.\n" +
			"Your job is to look at the history of attempts and decide if the subagent is stuck " +
			"in a loop, oscillating between different errors without progress, or otherwise runaway.\n\n" +
			"Analyze the history:\n" +
			"- Look at the syzlang programs and compilation/runtime execution errors in successive turns.\n" +
			"- Check if the subagent is oscillating (e.g. changing an argument from X to Y, " +
			"getting an error, changing it back to X, getting the previous error).\n" +
			"- Check if the subagent is repeating the exact same error for more than 3 turns " +
			"without any meaningful modification to the code structure.\n" +
			"- Check if it is making zero progress toward successful compilation/execution.\n\n" +
			"Decision Criteria:\n" +
			"- Set Stop = true if there is a clear loop, oscillation, or lack of progress.\n" +
			"- If setting Stop = true, provide a clear, concise and actionable Reason summarizing " +
			"the loop or why progress is blocked. This reason will be returned as an error to " +
			"the parent agent, helping it try a different strategy.\n" +
			"- Set Stop = false if the subagent is introducing new changes, trying new paths, " +
			"or making progress towards resolving the errors.",
	},
	Prompt: `{{if .IgnoreCallErrors}}CRITICAL INSTRUCTION: You are debugging a program where ` +
		`the target PC is expected to be in an error path. Thus, call errors (syscalls returning ` +
		`an error like EINVAL, EFAULT, etc.) are expected and acceptable.
` +
		`Do NOT try to fix call errors, and do NOT fail.
` +
		`You MUST treat the execution as successful even if there are call errors, as long as ` +
		`it compiles successfully (i.e. you got an ExecutionCachedID as response).
` +
		`Immediately yield by returning the ExecutionCachedID of the run.

{{end}}{{if .BaseTestSeed}}Base Test Seed: {{.BaseTestSeed}}

{{end}}Generator's Syzlang Program:
{{.SyzProgram}}`,
}

func diffPrograms(original, fixed string) string {
	// Ensure both strings end with a newline to avoid diffs on missing EOF.
	original = ensureTrailingNewline(original)
	fixed = ensureTrailingNewline(fixed)
	edits := myers.ComputeEdits(span.URIFromPath("original"), original, fixed)
	return fmt.Sprint(gotextdiff.ToUnified("original", "fixed", original, edits))
}

func ensureTrailingNewline(s string) string {
	if s != "" && !strings.HasSuffix(s, "\n") {
		return s + "\n"
	}
	return s
}
