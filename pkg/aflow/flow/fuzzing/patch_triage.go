// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzing provides workflows for triaging fuzzing-related patches and bug reports.
package fuzzing

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func init() {
	aflow.Register[ai.PatchTriageArgs, ai.PatchTriageResult](
		ai.WorkflowPatchTriage,
		"evaluate if a kernel patch series has functional impact worth fuzzing",
		&aflow.Flow{
			Root: aflow.Pipeline(
				readPatchDiff,
				&aflow.LLMAgent{
					Name:     "patch-evaluator",
					Model:    aflow.CoreModel,
					TaskType: aflow.FormalReasoningTask,
					Outputs: aflow.ValidatedLLMOutputs[patchEvalOutput](
						func(ctx *aflow.Context, state ai.PatchTriageArgs, args patchEvalOutput) (patchEvalOutput, error) {
							if args.Reasoning == "" {
								return args, aflow.BadCallError("reasoning must be provided")
							}
							if !args.WorthFuzzing && len(args.FocusSymbols) > 0 {
								return args, aflow.BadCallError("FocusSymbols must be empty if WorthFuzzing is false")
							}

							args.EnableConfigs = normalizeKernelConfigs(args.EnableConfigs)
							if err := validateKernelConfigs(state.TargetArch, state.KernelSrc, args.EnableConfigs); err != nil {
								return args, err
							}
							return args, nil
						},
					),
					Tools: aflow.Tools(
						grepper.Tool,
						codesearcher.FilesystemTools,
					),
					Instruction: patchTriageInstruction,
					Prompt:      patchTriagePrompt,
				},
				&aflow.If{
					Condition: "WorthFuzzing",
					Do: &aflow.LLMAgent{
						Name:     "kmsan-evaluator",
						Model:    aflow.CoreModel,
						TaskType: aflow.FormalReasoningTask,
						Outputs:  aflow.LLMOutputs[kmsanEvalOutput](),
						Tools: aflow.Tools(
							grepper.Tool,
							codesearcher.FilesystemTools,
						),
						Instruction: kmsanTriageInstruction,
						Prompt:      patchTriagePrompt,
					},
				},
			),
		},
	)
}

func normalizeKernelConfigs(configs []string) []string {
	var normalized []string
	for _, cfg := range configs {
		normalized = append(normalized, strings.TrimPrefix(cfg, "CONFIG_"))
	}
	return normalized
}

func validateKernelConfigs(targetArch, kernelSrc string, configs []string) error {
	if len(configs) == 0 {
		return nil
	}
	target := targets.Get("linux", targetArch)
	if target == nil {
		return fmt.Errorf("unknown target linux/%q", targetArch)
	}
	kconf, err := kconfig.Parse(target, filepath.Join(kernelSrc, "Kconfig"))
	if err != nil {
		return fmt.Errorf("failed to parse Kconfig: %w", err)
	}
	var badConfigs []string
	for _, cfg := range configs {
		if kconf.Configs[cfg] == nil {
			badConfigs = append(badConfigs, cfg)
		}
	}
	if len(badConfigs) > 0 {
		return aflow.BadCallError("the following configs do not exist in the kernel tree: %v", strings.Join(badConfigs, ", "))
	}
	return nil
}

type readPatchDiffArgs struct {
	KernelSrc string
}

type readPatchDiffResult struct {
	PatchDiff string
}

var readPatchDiff = aflow.NewFuncAction("read-patch-diff",
	func(ctx *aflow.Context, args readPatchDiffArgs) (readPatchDiffResult, error) {
		patch, err := osutil.RunCmd(time.Minute, args.KernelSrc, "git", "show", "HEAD")
		if err != nil {
			return readPatchDiffResult{}, err
		}
		return readPatchDiffResult{PatchDiff: string(patch)}, nil
	})

const patchTriageInstruction = `You are an expert Linux kernel maintainer and security engineer.
Your job is to review a provided patch series and evaluate whether it warrants fuzzing with syzkaller.

IMPORTANT: The changes have ALREADY been applied and committed as the HEAD commit in
your workspace. Do NOT rely on internal assumptions. You must actively use your code access
tools to inspect the actual source code, callers, and surrounding context.

================================================================================
1. CORE TRIAGE PHILOSOPHY
================================================================================
The goal of patch fuzzing is to discover crashes, regressions, exposed latent bugs,
and newly triggered assertions introduced by the patch series.

- REACHABILITY IS THE PRIMARY GATE:
  Fuzzing can only discover bugs in code that can actually execute in standard virtualized
  environments (GCE or QEMU, utilizing software-emulated devices like USB gadgets, netdev, tun/tap).
  If the modified code is structurally unreachable (see Section 2), it MUST NOT be fuzzed,
  regardless of whether it adds assertions or complex logic.

- DO NOT BLINDLY TRUST "NO FUNCTIONAL CHANGE" (NFCI) OR "REFACTORING" CLAIMS:
  Patch authors routinely label changes as "cleanups", "refactorings", or state
  "No functional change intended". Do NOT take these claims at face value.
  Code refactorings that rearrange logic, introduce helper functions, or alter state management
  in core subsystems frequently introduce subtle semantic shifts or uncover latent kernel bugs.
  If reachable executable code is modified or refactored, it MUST be fuzzed.

- NEW OR MODIFIED ASSERTIONS IN REACHABLE CODE MUST BE FUZZED:
  When a patch introduces or modifies runtime checks or assertions (e.g., WARN_ON*, VM_WARN_ON*,
  BUG_ON*, lockdep_assert*) in reachable code paths, it enforces new or stricter invariants.
  Even if the author believes the invariant always holds, fuzzing is essential to verify whether
  an unusual sequence of operations can violate it.

================================================================================
2. WHEN TO RETURN WorthFuzzing=false (NEGATIVE CRITERIA)
================================================================================
Return WorthFuzzing=false ONLY IF all modified code falls strictly into one or more of these categories:

- Non-kernel and non-executable changes:
  * Modifications to Documentation/, comments, or spelling fixes.
  * User-space directories, self-tests, samples, or scripts (e.g., tools/, samples/, scripts/, usr/)
    that do not affect the compiled kernel image (vmlinux) or kernel modules.
  * Purely decorative logging (e.g., message strings in pr_err, printk, dev_info) or tracepoints
    that do not alter control flow or data structures.
  * Build system or Kconfig changes that do not alter compiled C logic.
- Structurally unreachable hardware:
  * Vendor-specific PCIe switches, SmartNICs, or GPU drivers (e.g., mlxsw, pds_core, qed,
    ionic, amdgpu) requiring physical ASIC/PCIe cards not emulated in standard QEMU.
- Unreachable execution paths:
  * Driver teardown callbacks (.remove, .shutdown, pci_unregister_driver) executed only during
    physical PCI hot-unplug or manual sysfs driver unbinding.
  * Code paths exclusive to architectures other than the target architecture.

================================================================================
3. WHEN TO RETURN WorthFuzzing=true (POSITIVE CRITERIA)
================================================================================
Return WorthFuzzing=true whenever the patch touches reachable executable code, including:
- Core Subsystems:
  * Any logic modifications in memory management (mm/), synchronization/locking (kernel/locking/),
    BPF, scheduler, core networking, VFS, or syscall handling.
- Refactorings and Code Cleanups:
  * Any restructuring of reachable data structures, helper abstractions, or algorithm flows.
- Runtime Assertions and Defensive Checks:
  * Any introduction or alteration of assertions (WARN_ON*, VM_WARN_ON*, BUG_ON*, etc.) in reachable paths.
- Reachable Drivers and Protocols:
  * Drivers accessible via virtual buses (virtio, USB gadget, loopback, netlink, binder, sockets, etc.).

================================================================================
4. EXTRACTING FocusSymbols (PREVENTING DILUTION)
================================================================================
When WorthFuzzing=true, you must extract specific kernel functions into FocusSymbols to guide the fuzzer:

- AVOID UBIQUITOUS LIFECYCLE HOT-PATHS:
  Do NOT list generic, ubiquitous functions called by almost every program in the corpus
  (including, but not limited to: general memory allocators and deallocators, page fault
  and trap handlers, or core synchronization primitives; this is not an exhaustive list).
  Listing ubiquitous functions causes the fuzzer to classify thousands of unrelated tests as "focused",
  which severely dilutes fuzzing effort away from the actual changes.

- TARGET SPECIFIC FEATURE LOGIC AND ENTRYPOINTS:
  List functions that specifically implement the logic being added or altered, or direct API entrypoints
  for the subsystem feature under review.

- HANDLING STATIC INLINE FUNCTIONS IN HEADERS (.h):
  Compiler-inlined static functions (such as static inlines in mm/*.h or include/linux/*.h) lack
  distinct symbol addresses in vmlinux and cannot be targeted directly by symbol coverage filters.
  If the changes are primarily in static inline helpers, identify non-static, feature-specific caller
  functions in .c files that exercise them (avoiding ubiquitous lifecycle wrappers).

================================================================================
5. IDENTIFYING EnableConfigs
================================================================================
Identify any specific CONFIG_ options required to properly compile and reach the modified code:
- Inspect Kconfig files and #ifdef guards; do not make assumptions.
- Check "depends on" lines in Kconfig to include any non-standard parent subsystem configs needed.
- Strip any 'CONFIG_' prefix (e.g., return "NET_IPV4" instead of "CONFIG_NET_IPV4").`

const patchTriagePrompt = `Target architecture: {{.TargetArch}}

For your convenience, here is the diff of the changes:
{{.PatchDiff}}`

type patchEvalOutput struct {
	WorthFuzzing  bool     `jsonschema:"True if changes modify reachable code worth fuzzing."`
	FocusSymbols  []string `jsonschema:"Specific, non-ubiquitous kernel functions to focus fuzzing on."`
	EnableConfigs []string `jsonschema:"Kernel config flags required without CONFIG_ prefix."`
	Reasoning     string   `jsonschema:"Concise explanation of the fuzzing verdict."`
}

type kmsanEvalOutput struct {
	NeedsKMSAN     bool   `jsonschema:"True only if changes expose uninitialized memory risks."`
	KMSANReasoning string `jsonschema:"Reasoning contrasting KMSAN vs KASAN applicability."`
}

const kmsanTriageInstruction = `You are an expert Linux kernel security engineer specializing in kernel memory
error detectors (KASAN and KMSAN). Your job is to review the provided patch series and
determine if the code changes justify spawning a dedicated KMSAN (KernelMemorySanitizer)
fuzzing session in addition to standard KASAN fuzzing.

CRITICAL DISTINCTION BETWEEN KASAN AND KMSAN:
- Standard KASAN kernel builds (upstream-apparmor-kasan.config) already enable
  a comprehensive suite of debugging tools and sanitizers, including KASAN
  (out-of-bounds accesses, use-after-free, double free, invalid free), LOCKDEP
  (locking bugs and deadlocks), UB-sanitizers, and memory corruption checks.
- KMSAN (KernelMemorySanitizer) detects reads of UNINITIALIZED memory (stack, heap,
  or page allocations) and kernel-to-user memory info-leaks.

Rule: THERE IS NO SENSE IN RUNNING A KMSAN SESSION IF A BUG CAN BE CAUGHT BY KASAN,
LOCKDEP, OR OTHER STANDARD BUG DETECTORS.
A dedicated KMSAN fuzzing session incurs significant resource costs. You must ONLY
set NeedsKMSAN=true if the code changes introduce or expose UNINITIALIZED MEMORY risks
that are detected ONLY by KMSAN.

Look holistically at the patch series and surrounding code. Even if no direct
uninitialized field accesses or new buffer allocations are added in the diff itself,
a patch may alter control flow, bounds checking, or data length calculations in ways
that change how the rest of the code operates on existing buffers (e.g. allowing
uninitialized stack/heap memory to be read, copied to user space, or used in control
flow). Do not hesitate to use your code access tools to inspect the surrounding code,
called functions, and callers.

Set NeedsKMSAN=true ONLY IF the patch introduces or modifies:
1. Kernel structures sent to user space (via copy_to_user, put_user, netlink skb
   attributes, ioctl output arguments, socket options, or BPF buffers) where fields
   or structure padding might not be fully initialized/zeroed.
2. Conditional logic or branching that depends on potentially uninitialized variables
   or struct fields.
3. Allocation or initialization of complex data structures where uninitialized fields
   could be read later in reachable code paths.
4. Bounds checks, lengths, or logic in a way that allows surrounding code to access
   uninitialized bytes of existing buffers.

Set NeedsKMSAN=false IF:
- The code changes primarily risk out-of-bounds access, array overflows, NULL pointer
  dereferences, locking deadlocks, or use-after-free bugs (these are already caught
  by KASAN, LOCKDEP, or standard bug detectors).
- All stack/heap structures touched or introduced by the patch are fully zeroed
  or initialized (e.g. using = {0}, memset, kzalloc) before being read or copied.
- The patch does not introduce any risk of uninitialized memory usage or info-leaks.

Use your code access tools to inspect the surrounding code if necessary, then provide
detailed KMSANReasoning contrasting KASAN vs KMSAN applicability for this patch.`
