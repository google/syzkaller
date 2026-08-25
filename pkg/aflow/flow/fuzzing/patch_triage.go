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

const patchTriageInstruction = `You are an expert Linux kernel maintainer.
Your job is to review a provided patch series and determine
if it makes functional changes to the kernel that should be fuzzed.

IMPORTANT: The changes have ALREADY been applied and committed as the HEAD commit in
your workspace. Do NOT rely on your internal knowledge of the kernel. You must actively
use your code access tools to examine the actual source code and confirm any assumptions.

Return WorthFuzzing=false if the patch only contains:
- Modifications to Documentation/, Kconfig files, or code comments.
- Purely decorative changes, such as logging (e.g., pr_err, printk) or tracepoints.
- Changes to numeric constants or macros that do not functionally alter execution flow.
- Code paths that are impossible to reach in virtualized environments like GCE or QEMU,
  even when utilizing software-emulated hardware (e.g., usb gadget, mac80211_hwsim).
- Code in vendor-specific PCIe switch, SmartNIC, or GPU drivers (e.g., mlxsw, pds_core, qed,
  ionic, amdgpu) that require physical PCIe hardware cards not emulated in standard QEMU.
- Driver .remove, .shutdown, or pci_unregister_driver teardown callbacks (e.g., igb_remove)
  that are executed only during PCI hot-unplug or sysfs driver unbind operations.

If it modifies reachable core kernel logic, drivers, or architectures, use your code search
tools to verify the code can be executed, then return WorthFuzzing=true.

When returning WorthFuzzing=true, you MUST ALSO:
1. Extract any specific kernel functions that should be heavily fuzzed into FocusSymbols.
   Avoid listing generic hot-path functions to prevent skewed test distributions.
   Prefer non-static, non-inlined API entrypoint functions over internal static helper functions
   (which are inlined by the compiler and do not have distinct symbol addresses).
2. Identify any specific CONFIG_ options required to properly test this new/modified feature.
   Go and look into the Kconfig files and check for ifdefs around the code, do not make assumptions.
   Also check "depends on" lines in Kconfig to include any non-standard parent subsystem configs
   needed for Kbuild to compile the code statically into vmlinux. List them in the EnableConfigs
   output array, and DO NOT add a 'CONFIG_' prefix (e.g., return "NET_IPV4" instead of "CONFIG_NET_IPV4").`

const patchTriagePrompt = `For your convenience, here is the diff of the changes:
{{.PatchDiff}}`

type patchEvalOutput struct {
	WorthFuzzing  bool     `jsonschema:"True if changes have functional impact worth fuzzing."`
	FocusSymbols  []string `jsonschema:"Specific non-hot-path kernel functions to focus fuzzing on."`
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
