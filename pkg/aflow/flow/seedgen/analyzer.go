// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type AnalyzerQuery struct {
	Query string `jsonschema:"The specific research task or question."`
}

type analyzerState struct {
	EnvironmentPrompt string `json:",omitempty"`
}

var ReachabilityAnalyzer = aflow.LLMTool[analyzerState, AnalyzerQuery]{
	Name: "reachability-analyzer",
	Description: `Use this tool to research how userspace can reach specific kernel code paths or branches.
It specializes in:
1. Finding userspace-facing entry points (syscalls, ioctls, netlink, sysfs/procfs, socket options).
2. Identifying branch preconditions and required subsystem state leading to a target line.
3. Cross-referencing kernel C code with Syzkaller syscall descriptions (sys/linux/*.txt)
   and pseudo-syscalls (syz_*).
4. Checking kernel build options in .config.
DO NOT use this tool for git history/blame or generic code refactoring questions;
use it specifically to discover reachable trigger paths from userspace into the kernel.`,
	Model:    aflow.CoreModel,
	TaskType: aflow.FormalReasoningTask,
	Tools: aflow.Tools(
		kernel.ToolConfigGrep,
		codesearcher.Tools,
		grepper.Tool,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	Instruction: `You are a pragmatic reachability and entrypoint researcher.
Your task is to find the most direct and straight-forward userspace call path and
prerequisites to reach the requested target.
There are two distinct domains you might need to research, with specific tools for each:
1. Linux Kernel Source Tree & Environment: Use 'codesearch-*' tools and '{{.toolGrepper}}' to find struct layouts,
macro definitions, and function implementations in the target kernel. Use '{{.toolKernelConfigGrep}}' to check
kernel build options (.config) or target architecture settings.
When researching a component, actively check and read the kernel documentation under the 'Documentation/'
directory in the source tree to understand the component, its module parameters, and its expected setup/usage sequence.
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

## RESEARCH CONSTRAINTS
- Focus STRICTLY on caller branch conditions, ` + "`if`" + ` statements, and
  ioctl prerequisites leading directly to the target line.
- DO NOT read deep low-level library helpers (printk, vsprintf, alloc_page, mutex locks).

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
	Prompt: `{{if .EnvironmentPrompt}}Target Environment:
{{.EnvironmentPrompt}}

{{end}}Query: {{.Query}}`,
}
