package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
)

type CodeFixerArgs struct {
	SyzProgram       string `jsonschema:"The syzlang program that needs debugging."`
	IgnoreCallErrors bool   `jsonschema:"Ignore syscall call errors if target is in an error path."`
}

var CodeFixer = &aflow.LLMTool[struct{}, CodeFixerArgs]{
	Name:     "code-fixer",
	Model:    aflow.TemporaryFlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Description: "A subagent tool that takes a syzlang program and repeatedly executes it " +
		"until it has no compilation or runtime call errors (e.g. EINVAL). " +
		"If IgnoreCallErrors is set to true, it will ignore execution call errors " +
		"and only fix compilation/syntax errors. Returns the ExecutionCachedID of the run.",
	Instruction: "You are an expert syzkaller seed debugger.\n" +
		"The parent Generator has provided an initial syzlang program to reach the target.\n" +
		"Your job is ONLY to debug any syntax/compilation or call errors in the provided syzlang program.\n" +
		"Do NOT generate new logic to reach something or debug why something is not reached.\n" +
		"If the seed executes successfully (i.e. returns an ExecutionCachedID and " +
		"either CallErrors is empty or you are instructed to ignore call errors), " +
		"you MUST immediately yield by returning the ExecutionCachedID as your final reply. " +
		"It is NOT your job to reason or double check the program.\n" +
		"You MUST:\n" +
		"1. Execute the syzlang program using '{{.toolExecuteSeed}}'.\n" +
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

{{end}}Generator's Syzlang Program:
{{.SyzProgram}}`,
}
