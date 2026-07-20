package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type AnalyzerQuery struct {
	Query string `jsonschema:"The specific research task or question."`
}

var SeedgenAnalyzer = aflow.LLMTool[struct{}, AnalyzerQuery]{
	Name: "seedgen-analyzer",
	Description: "Use this tool to explore the codebase. Provide a specific query, " +
		"and it will search the codebase and return a concise summary of the findings.",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Tools: aflow.Tools(
		crash.GetEnvironment,
		codesearcher.Tools,
		grepper.Tool,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	Instruction: `You are a pragmatic codebase researcher.
Your task is to find the most direct and straight-forward answer to the requested query.
There are two distinct domains you might need to research, with specific tools for each:
1. Linux Kernel Source Tree & Environment: Use 'codesearch-*' tools and 'grepper' to find struct layouts,
macro definitions, and function implementations in the target kernel. Use 'get-environment' to check
kernel build options (.config) or target architecture settings.
IMPORTANT: These tools search the Linux kernel ONLY.
` + syzlang.DomainBoundaryConstraints + `

Search Guidance:
- Focus on Core Subsystems & Interfaces: When researching entry points or call paths, focus on primary
kernel interfaces and userspace-accessible entry points (e.g., system calls, ioctls, file operations,
sysfs/procfs nodes, or socket interfaces). Avoid deep dives into low-level hardware or vendor-specific
driver glue code unless the target PC itself resides within that specific driver.
- Limit Traversal Depth: Avoid recursively tracing call chains or indirect callers too deep.
Focus on identifying the immediate userspace-facing interface (e.g., the syscall, ioctl, or file operation
handler) that initiates the path.

` + syzlang.SandboxConstraints + `

` + syzlang.PseudoSyscallConstraints + `

- Leverage Parallel Tool Calls: If you need to verify multiple potential paths or look up multiple
symbols, dispatch these tool calls in parallel within a single turn to minimize round-trips.
Do NOT attempt to write or execute seeds (aka c or syzlang programs).
Once you have found the necessary information, return a clean, concise and detailed summary of the
findings in your final reply. Always include the file name and line number if you are referring to code.
(CRITICAL INSTRUCTION) Focus on the most actionable information (e.g., specific syscalls, ioctls, sysfs files,
or interface commands) and do not list excessive or irrelevant caller paths.` +
		common.InstructionDontMakeAssumptionsAboutSourceCode,
	Prompt: "Query: {{.Query}}",
}
