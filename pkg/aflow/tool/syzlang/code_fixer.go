package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
)

type CodeFixerArgs struct {
	BaseTestSeed string `jsonschema:"Optional path to a test seed file. MUST be provided if requested by generator."`
	SyzProgram   string `jsonschema:"The syzlang program that needs debugging."`
}

var CodeFixer = &aflow.LLMTool[struct{}, CodeFixerArgs]{
	Name:     "code-fixer",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Description: "A subagent tool that takes a syzlang program and repeatedly executes it " +
		"until it has no compilation or runtime call errors (e.g. EINVAL). " +
		"Returns the ExecutionCachedID of the successful run.",
	Instruction: "You are an expert syzkaller seed debugger.\n" +
		"The parent Generator has provided an initial syzlang program to reach the target.\n" +
		"You may also be provided with a Base Test Seed path (e.g. test/vusb_cdc_ecm) which sets up the environment.\n" +
		"These test seeds are not for you to understand in detail, but only to set up some environment " +
		"like devices or file system.\n" +
		"Your job is ONLY to debug any syntax/compilation or call errors in the provided syzlang program.\n" +
		"Do NOT generate new logic to reach something or debug why something is not reached.\n" +
		"If the seed executes successfully (i.e. returns an ExecutionCachedID and CallErrors is empty), " +
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
		"3. Execute again until you get one successful execution (i.e. no call errors or compiler errors).\n" +
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
	Prompt: "{{if .BaseTestSeed}}Base Test Seed: {{.BaseTestSeed}}\n\n{{end}}" +
		"Generator's Syzlang Program:\n{{.SyzProgram}}",
}
