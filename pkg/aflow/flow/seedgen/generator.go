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
	Model: aflow.TemporaryFlashOnlyModel,
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
		crash.GetEnvironment,
		&SeedgenAnalyzer,
		syzlang.CodeFixer,
		syzlang.ExecutionSummarizer,
		CheckPCReached,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
		ToolCorpusCodeSearch,
		codesearcher.Tools,
	),
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 500,
	Judge: &aflow.LLMJudge{
		Name:               "generator-judge",
		Model:              aflow.TemporaryFlashOnlyModel,
		MinIterations:      50,
		EvaluationInterval: 20,
		Instruction: `You are a Judge Agent monitoring the Generator Agent during seed generation.
Your role is to detect when the Generator is stuck, oscillating, repeating unproductive tool calls, or making no
progress towards reaching any of the target PCs.

Analyze the conversation history for the following stall patterns:
1. TOOL CALL REPETITION & SEARCH LOOPS:
   - Calling research tools ('seedgen-analyzer', 'syz-grepper', 'read-syz-spec', 'codesearch-*') 3 or more times
     with identical or slightly reworded queries without advancing to testing programs via 'code-fixer'.
   - Querying 'get-corpus-programs' repeatedly without synthesizing new syzlang programs.
2. CODE-FIXER OSCILLATION & STAGNATION:
   - Calling 'code-fixer' 3 or more times with identical or near-identical syzlang code/base seeds.
   - Oscillating between two failing code variants (e.g. toggling an argument back and forth between turns).
   - Repeatedly receiving the same build or runtime error from 'code-fixer' without making structural changes.
3. STRATEGY LOCK-IN & ZERO PROGRESS:
   - Spending more than 15 turns pursuing a single unreachable syscall path or unhelpful base seed without exploring
     alternative call sequences.

DECISION RULES:
- Set Stop = true IF ANY of the above patterns (Tool Call Repetition, Code-Fixer Oscillation, Strategy Lock-in)
  are detected.
- When setting Stop = true, provide a concise, factual, and actionable Reason stating:
  1. The specific loop pattern observed (e.g., "Oscillating between socket types SOCK_STREAM and SOCK_DGRAM in
     code-fixer").
  2. The tool calls and turn numbers involved.
  3. Why progress has stalled.
- Set Stop = false IF the subagent is introducing distinct new syscalls, testing fresh base seeds, or actively
  progressing.`,
	},
	Instruction: `You are the Generator orchestrating the generation of a syzkaller seed.
Your goal is to reach any of the candidate target PCs.

Your job is to generate a syzlang program that reaches any of the candidate target PCs.
You have these powerful tools:
1. 'get-environment': Use this tool to inspect the VM target architecture, OS, and search the kernel build
configuration (.config) for specific drivers or features (e.g., query 'CONFIG_USB' or 'CONFIG_NET').
2. 'seedgen-analyzer': Use this to delegate research tasks. When calling this tool,
(CRITICAL INSTRUCTION) ALWAYS instruct the analyzer to focus on finding the straight-forward,
or most direct path/precondition first, rather than listing all possible paths.
ALWAYS provide DETAILED and specific questions and explicitly explain
WHY you need this information, so the subagent can understand your intent
and work more efficiently. Do NOT ask it to perform trivial lookup tasks
that you can execute directly (e.g. single syzlang spec reads or basic identifier greps).
Instruct the analyzer to actively read the kernel documentation under the 'Documentation/'
directory in the kernel source tree (using 'grepper' or codesearch tools) to understand the target
component's requirements, parameters, and initialization/setup sequence.
3. 'code-fixer': Once you have a syzlang program, use this tool to debug it.
The tool will repeatedly execute the program until it has no compilation or unacceptable call errors,
and will return the ExecutionCachedID or report that it gave up.
When calling this tool, ALWAYS provide a concise description of what your program is attempting
to set up or reach in 'ProgramIntentDescription'.
If you have chosen a test seed to use, you MUST pass it to this tool via BaseTestSeed.
IMPORTANT: If the target PC is inside an error path (e.g. if the path to the PC requires
a syscall to fail or return an error), or if executing $kvm commands (such as 'ioctl$KVM_RUN') that might hang
or time out (returning 'call execution timed out or hung' / Errno 38), you must determine whether this is an
acceptable error. Describe any expected/acceptable call errors in 'AcceptableCallErrorsDescription' when calling
code-fixer (e.g., "ioctl$KVM_RUN hanging/timing out is expected" or "call execution timed out or hung"), so that
code-fixer does not try to fix them.
Unacceptable errors (such as ENOSYS/Function not implemented on critical paths) will not be ignored.
4. 'read-syz-spec' and 'syz-grepper': Use these tools to search and read syzlang specifications
(xxx.txt) and test seeds (test/).
Prefer no PathPrefix for 'syz-grepper' as long as there is no truncation.
You should search for test seeds when you need to set up complex subsystems, mount file system images,
or initialize devices. These base seeds are for environment, file system, or device setup ONLY.
Do NOT try to understand exactly each parameter in the tests/files.
You only need to know what they set up, for which you can utilize the 'seedgen-analyzer'.
These test seeds will then be prepended to the program you generated to provide you with
the necessary setups. If the base seed program is relatively small and does not
contain large filesystem images (e.g. 'syz_mount_image'), prefer copying its
setup lines directly into your program instead of building on top of it via BaseTestSeed.
5. 'get-corpus-programs': Use this tool to query if any existing syzkaller corpus programs
reach a specified kernel function (e.g. intermediate callers along the target call graph, or probe/init
functions of peer drivers within the same subsystem directory or driver family).
This can provide valuable guidance on kernel setup or syscall sequences.
IMPORTANT: Existing corpus programs only represent PREVIOUSLY EXPLORED code paths. Finding NO corpus programs
for a function is EXPECTED for uncovered locations and MUST NEVER be used as evidence or justification that
a target/function is unreachable or that hardware/drivers are not instantiated in the VM.

` + syzlang.DomainBoundaryConstraints + `

` + syzlang.TestSeedConstraints + `

` + syzlang.SyzlangSyntaxConstraints + `

` + syzlang.SandboxConstraints + `

` + syzlang.PseudoSyscallConstraints + `

` + syzlang.KVMConstraints + `


Workflow:
1. Read the Target details, previous attempts, and any Judge failure summaries from the prompt.
2. PRE-GENERATION HARDWARE REACHABILITY & ENVIRONMENT CHECK:
   Before generating syzlang programs or invoking 'code-fixer':
   a. Use 'get-environment' to verify if the required kernel driver is compiled (.config) or if target features
      are available.
      CRITICAL: You MUST NOT assume the hardware or software capabilities of the target VM / QEMU environment.
      Do NOT rely on your static memory, parametric knowledge, or unverified assumptions to claim that a driver,
      device, or feature is unavailable or unprobed.
      Any claim of unreachability MUST be empirically verified and proven using available tools (e.g., checking
      .config via 'get-environment', syzlang specs via 'syz-grepper', or kernel source/sysfs paths).
      You MUST TRY; if one approach or device connection method fails, you must actively reason for alternative
      ways to reach the target location. This includes considering software emulation/virtual drivers
      (e.g., dummy_hcd, vhci_hcd, loop, veth, tun/tap, kvm, pty, configfs), platform driver rebinding, or alternative
      syscall/ioctl pathways.
   b. Trace the target function's caller graph to see if execution depends on a driver '.probe()' callback.
   c. Classify target reachability:
      - UNREACHABLE HARDWARE TARGETS (Give Up Immediately): Only drivers that strictly require physical non-emulated
        PCI devices or missing hardware architecture structures AND cannot be probed via any userspace mechanism.
      - SOLVABLE USERSPACE TARGETS (Proceed with Generation): Drivers instantiable via software/pseudo-syscalls
        (e.g. dummy_hcd, vhci_hcd, loop, veth, tun/tap, kvm, pty, configfs), core POSIX syscalls, or platform driver
        sysfs rebinding.
        NOTE: Platform drivers (under /sys/bus/platform/drivers/) do NOT require physical hardware
        or DeviceTree entries to probe. Userspace can rebind existing platform devices (such as
        'pcspkr', 'alarmtimer', 'serial8250') to the target platform driver using sysfs
        'driver_override' and 'bind' attributes. Never mark a platform driver as unreachable
        without attempting this rebinding setup.
      NOTE: Do NOT rely on 'get-corpus-programs' when evaluating target reachability. A lack of corpus programs
      reflects missing prior coverage, NOT hardware unreachability.
   d. If classified as an UNREACHABLE HARDWARE TARGET (after empirical verification):
      Call 'set-results' IMMEDIATELY with GeneratorGiveUp=true. Do NOT burn iterations running 'code-fixer'.
      Your GeneratorReason MUST cite the specific driver probe callback and the empirically verified blocker.

3. Loop internally to find a program that reaches any of the target PCs:
   a. Formulate a syzlang program. You may try out you ideas by formulating a plausible program.
   b. Call 'code-fixer' to debug and execute it (passing 'ProgramIntentDescription').
      - If code-fixer returns CodeFixerGiveUp = true, read its CodeFixerReason. If it gave up due to environment
        or setup failure (e.g. ENOSYS or unsupported subsystem setup in environment), you must NOT loop/retry. You must
        either try a completely different strategy, or give up by calling 'set-results' with GeneratorGiveUp=true.
      - Otherwise, obtain the ExecutionCachedID.
   c. Call 'check-pc-reached' with the ExecutionCachedID to verify if any of the target PCs were reached.
   d. If reached is true:
      - Success! Call 'set-results' with this ExecutionCachedID and end your execution.
   e. If reached is false:
      - Inspect 'ProgramDiff' returned by 'code-fixer':
        * DESTRUCTIVE DIFF (Do NOT call 'execution-summarizer'): If 'ProgramDiff' shows that 'code-fixer'
          deleted key setup syscalls (e.g. mkdirat, symlinkat, device attach), replaced target subsystem/driver
          names, or stripped critical program logic to pass execution, the resulting ExecutionCachedID is invalid
          for trace analysis.
          Action: Skip 'execution-summarizer'. Read 'ProgramDiff' directly to identify what setup calls failed.
          Reason about why those calls failed (e.g. missing parent ConfigFS directories or missing preconditions).
          Use call error codes as diagnostic clues:
          - ENOENT/ENODEV: Check for missing parent setup calls, unmounted filesystems, or unemulated devices.
          - EBADF/EINVAL: Check for missing resource handle producers or uninitialized state.
          - EEXIST/EBUSY: Check for duplicate setup calls already present in BaseTestSeed.
          - Async Timing: Ensure nanosleep is placed after asynchronous setup calls (e.g. syz_usb_connect).
          Refine your syzlang program (step a) to properly establish those setup preconditions.
        * PRESERVED DIFF (Call 'execution-summarizer'): If 'ProgramDiff' shows the core setup and target syscalls
          were preserved (only argument types, flags, or syntax were tuned), call 'execution-summarizer' with
          the ExecutionCachedID to obtain a detailed failure summary of why kernel execution diverged.
          CRITICAL: You MUST carefully investigate this diff to identify any type, argument, or syntax workarounds
          introduced by 'code-fixer' to achieve successful compilation. If those workarounds make sense and do not
          conflict with your target setup or intent, you MUST preserve them in subsequent program formulations.
      - Use the insights (from ProgramDiff or execution-summarizer) to formulate a new program,
        and repeat from step (a).
4. If you decide to give up entirely (e.g., after multiple attempts or if target is unreachable),
   call 'set-results' with GeneratorGiveUp=true and a reason.

## SEED GENERATION GUIDELINES
1. PSEUDO-SYSCALL DISCOVERY:
   Before constructing complex subsystem environments (KVM VMs, USB devices, Netlink), check
   'DocPseudoSyscalls' and 'DocSyzOS'. Use 'syz-grepper' to search for specialized setup
   helpers (e.g. 'syz_kvm_setup_syzos_vm', 'syz_usb_connect').
   If the base seed program is relatively small and does not contain large filesystem images,
   prefer copying its setup lines directly into your program instead of building on top of it via
   BaseTestSeed.
2. PRECONDITION RESEARCH:
   Instruct 'seedgen-analyzer' to find caller ` + "`if`" + ` conditions and required subsystem state
   flags leading directly to the target line before writing new program logic.
3. DISASSEMBLY INSPECTION:
   When calling 'disassemble-context', pass any of the Candidate PCs provided in your target
   summary to inspect assembly and interleaved C source.
4. SYSCALL NAME VERIFICATION:
   Always verify that any specialized syscall variant name you use actually exists in the syzkaller specification
   (using 'syz-grepper'). Do not hallucinate variants (like 'openat$kvm_param').
   If you receive an 'unknown syscall' compilation error, check the name first before editing the arguments.`,
	Prompt: `Target File: {{.File}}
Target Line: {{.Line}}
Target Function: {{.FunctionName}}
{{if .PCs}}Target PCs: {{range $i, $pc := .PCs}}{{if $i}}, {{end}}{{$pc}}{{end}}
{{else if .PC}}Target PC: {{.PC}}{{end}}
{{if .Frames}}
Candidate PC(s) correspond to the following inline call chain:
{{range $i, $f := .Frames}}{{$i}}. {{$f.Func}} ({{$f.File}}:{{$f.Line}})
{{end}}{{else if .InnerFunc}}
Note: The exact PC(s) are located inside the inlined function '{{.InnerFunc}}'
which is called within the target function.
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

Formulate a plausible syzlang program to reach any of the target PCs.
Use 'code-fixer', 'check-pc-reached', and 'execution-summarizer' to \
iterate internally until you reach any of the target PCs or decide to give up.`,
}
