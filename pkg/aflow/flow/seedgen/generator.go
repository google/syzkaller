package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type GeneratorOutputs struct {
	ExecutionCachedID string `jsonschema:"Cached ID of your final attempt. MUST be provided unless giving up."`
	GeneratorGiveUp   bool   `jsonschema:"Set true if target is unreachable."`
	GeneratorReason   string `jsonschema:"Reason for giving up."`
}

var GeneratorAgent = &aflow.LLMAgent{
	Name:  "seed-generator",
	Model: aflow.Temporary35FlashOnlyModel,
	Outputs: aflow.ValidatedLLMOutputs(
		func(ctx *aflow.Context, state struct{}, outputs GeneratorOutputs) (GeneratorOutputs, error) {
			if !outputs.GeneratorGiveUp {
				if outputs.ExecutionCachedID == "" {
					return outputs, aflow.BadCallError("must provide ExecutionCachedID if not giving up")
				}
				_, _, err := crash.LoadSeedProgramDetails(ctx, outputs.ExecutionCachedID)
				if err != nil {
					return outputs, aflow.BadCallError("invalid ExecutionCachedID %q: %v", outputs.ExecutionCachedID, err)
				}
			}
			return outputs, nil
		}),
	Tools: aflow.Tools(
		&SeedgenAnalyzer,
		syzlang.CodeFixer,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	TaskType: aflow.FormalReasoningTask,
	Instruction: "You are the Generator orchestrating the generation of a syzkaller seed.\n" +
		"Your goal is to reach a specific target PC.\n\n" +
		"Your job is to generate a syzlang program that reaches the target PC.\n" +
		"You have these powerful tools:\n" +
		"1. 'seedgen-analyzer': Use this to delegate clearly formulated but " +
		"broad research tasks (e.g. 'How do I reach function X?', " +
		"'What are the preconditions for this path?'). When calling this tool, " +
		"(CRITICAL INSTRUCTION) ALWAYS provide DETAILED and specific questions and explicitly explain " +
		"WHY you need this information, so the subagent can understand your intent " +
		"and work more efficiently. Do NOT ask it to perform " +
		"narrow or specific lookups like 'query what is in xyz.txt' " +
		"or 'search for syz_fs_mount'. The analyzer works best with " +
		"high-level goals.\n" +
		"2. 'code-fixer': Once you have a syzlang program, use this tool to " +
		"debug it. The tool will repeatedly execute the program until it has no " +
		"compilation or call errors, and will return the ExecutionCachedID. " +
		"If you have chosen a test seed to use, you MUST pass it to this tool via BaseTestSeed.\n" +
		"3. 'read-syz-spec' and 'syz-grepper': Use these tools to search and read syzlang " +
		"specifications (sys.txt) and test seeds (test/).\n" +
		"You should search for test seeds when you need to set up complex " +
		"subsystems, mount file system images, or initialize devices. " +
		"These base seeds are for environment, file system, or device setup ONLY.\n" +
		"Do NOT try to understand exactly each parameter in the tests/files. " +
		"You only need to know what they set up, for which you can utilize " +
		"the 'seedgen-analyzer'. These test seeds will then be prepended " +
		"to the program you generated to provide you with the necessary setups.\n\n" +
		"Workflow:\n" +
		"1. Read the Target details, previous attempts, and the failure summary from the prompt.\n" +
		"2. If you need more information about the kernel state or functions, call 'seedgen-analyzer'.\n" +
		"3. Formulate a new syzlang program to reach the PC and call 'code-fixer' to transpile and debug it.\n" +
		"4. Once 'code-fixer' successfully returns an ExecutionCachedID, call 'set-results' with it. " +
		"The pipeline will verify coverage externally and restart the loop if it failed.\n" +
		"5. If you decide to give up entirely, call 'set-results' with GeneratorGiveUp=true and a reason.\n",
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
Target PC: {{printf "0x%x" .PC}}
{{if .Frames}}
PC corresponds to the following inline call chain:
{{range $i, $f := .Frames}}{{$i}}. {{$f.Func}} ({{$f.File}}:{{$f.Line}})
{{end}}{{else if .InnerFunc}}
Note: The exact PC is located inside the inlined function '{{.InnerFunc}}' which is called within the target function.
{{end}}

Function Context:
{{.FunctionSource}}

{{if .IndirectCallers}}
Indirect Callers of Target Function:
{{.IndirectCallers}}
{{end}}
{{.DescriptionFilesPrompt}}

{{$lastID := .LastFailedExecutionCachedID}}
{{$lastBase := .LastFailedBaseTestSeed}}
{{$lastGen := .LastFailedGeneratedSyz}}
{{if $lastID}}
---
Last Loop's Failed Attempt ExecutionCachedID: {{$lastID}}
{{if $lastBase}}
Base Test Seed: {{$lastBase}}
{{end}}
Generated Syz: 
{{$lastGen}}
---
{{end}}

{{if .LastFailureSummary}}
---
Failure Summary of Last Attempt:
{{.LastFailureSummary}}
---
{{end}}

Formulate a plausible syzlang program quickly based on the context. \
Use 'code-fixer' to execute and debug it. Output the resulting \
ExecutionCachedID using set-results to yield control back to the pipeline.`,
}
