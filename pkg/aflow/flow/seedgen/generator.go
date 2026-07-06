// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
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
		syzlang.ExecutionSummarizer,
		CheckPCReached,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
		codesearcher.Tools,
	),
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 1000,
	Judge: &aflow.LLMJudge{
		Name:               "generator-judge",
		Model:              aflow.Temporary35FlashOnlyModel,
		MinIterations:      300,
		EvaluationInterval: 30,
		Instruction: "You are a Judge Agent monitoring the Generator Agent.\n" +
			"The Generator is trying to reach a target PC by generating and testing programs in a loop.\n" +
			"Decide if the Generator is stuck, oscillating, or making no progress.\n" +
			"Set Stop = true if it has made more than 3 attempts (code-fixer calls) without getting closer to the target PC.",
	},
	Instruction: `You are the Generator orchestrating the generation of a syzkaller seed.
Your goal is to reach a specific target PC.

Your job is to generate a syzlang program that reaches the target PC.
You have these powerful tools:
1. 'seedgen-analyzer': Use this to delegate research tasks. When calling this tool,
(CRITICAL INSTRUCTION) ALWAYS instruct the analyzer to focus on finding the straight-forward,
or most direct path/precondition first, rather than listing all possible paths.
ALWAYS provide DETAILED and specific questions and explicitly explain
WHY you need this information, so the subagent can understand your intent
and work more efficiently. Do NOT ask it to perform
narrow or specific lookups like 'query what is in xyz.txt'
or 'search for syz_fs_mount'.
2. 'code-fixer': Once you have a syzlang program, use this tool to debug it.
The tool will repeatedly execute the program until it has no compilation or call errors,
and will return the ExecutionCachedID.
If you have chosen a test seed to use, you MUST pass it to this tool via BaseTestSeed.
IMPORTANT: If the target PC is inside an error path (e.g. if the path to the PC requires
a syscall to fail or return an error), you must set IgnoreCallErrors=true when calling code-fixer,
so that it doesn't try to fix expected call errors.
3. 'read-syz-spec' and 'syz-grepper': Use these tools to search and read syzlang specifications
(xxx.txt) and test seeds (test/).
(CRITICAL INSTRUCTION) DO NOT try to use syz-grepper and read-syz-spec for Linux files, headers,
or runtime paths (e.g. 'sys/class/...', 'sys/devices/...', 'sys/*.h' headers like 'sys/socket.h' etc.).
Use codesearch-* tools instead for Linux kernel files, POSIX headers, or sysfs/procfs paths.
To find a test seed that sets up a specific device or subsystem, use 'syz-grepper' with
PathPrefix='test' to search for relevant syscalls (e.g. 'syz_emit_ethernet' or 'tun')
inside the test seed files. Do NOT try to search for filenames directly via Expression.
Prefer no PathPrefix for 'syz-grepper' as long as there is no truncation.
You should search for test seeds when you need to set up complex subsystems, mount file system images,
or initialize devices. These base seeds are for environment, file system, or device setup ONLY.
Do NOT try to understand exactly each parameter in the tests/files.
You only need to know what they set up, for which you can utilize the 'seedgen-analyzer'.
These test seeds will then be prepended to the program you generated to provide you with
the necessary setups.
To use syscalls or setup devices more conveniently, you should look for pseudo syscalls starting
with ` + "`" + `long syz_*` + "`" + ` in the executor header files (under executor/ directory).
Using these pseudo syscalls in your syzlang program can be much more convenient than using the raw syscalls.

Workflow:
1. Read the Target details, previous attempts, and any Judge failure summaries from the prompt.
2. Loop internally to find a program that reaches the target PC:
   a. Formulate a syzlang program.
   b. Call 'code-fixer' to debug and execute it, obtaining an ExecutionCachedID.
   c. Call 'check-pc-reached' with the ExecutionCachedID to verify if the target PC was reached.
   d. If reached is true:
      - Success! Call 'set-results' with this ExecutionCachedID and end your execution.
   e. If reached is false:
      - Call 'execution-summarizer' with the ExecutionCachedID to get a detailed failure summary.
      - Use the failure summary details to formulate a new (improved) program, and repeat from step (a).
3. If you decide to give up entirely (e.g., after multiple attempts or if target is unreachable),
   call 'set-results' with GeneratorGiveUp=true and a reason.`,
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

{{if .LastFailedHistorySummary}}
---
Warning: The previous attempt got stuck and was terminated by the Judge. 
Summary of the failure:
{{.LastFailedHistorySummary}}
Use this info to avoid repeating the same loops or strategies.
---
{{end}}

Formulate a plausible syzlang program to reach the target PC.
Use 'code-fixer', 'check-pc-reached', and 'execution-summarizer' to \
iterate internally until you reach the target PC or decide to give up.`,
}
