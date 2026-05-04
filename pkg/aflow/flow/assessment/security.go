// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type assessmentSecurityInputs struct {
	CrashReport  string
	ReproSyz     string
	ReproC       string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

type securityOutputs struct {
	Exploitable       bool `jsonschema:"Analysis result: Exploitable."`
	DenialOfService   bool `jsonschema:"Analysis result: Denial Of Service."`
	Unprivileged      bool `jsonschema:"Analysis result: Accessible From Unprivileged Processes."`
	UserNamespace     bool `jsonschema:"Analysis result: Accessible From User Namespaces."`
	VMGuestTrigger    bool `jsonschema:"Analysis result: VM Guest Trigger."`
	VMHostTrigger     bool `jsonschema:"Analysis result: VM Host Trigger in The Confidetial Computing Context."`
	NetworkTrigger    bool `jsonschema:"Analysis result: Ethernet Network Trigger."`
	RemoteTrigger     bool `jsonschema:"Analysis result: Other Remote Trigger."`
	PeripheralTrigger bool `jsonschema:"Analysis result: Peripheral Trigger."`
	FilesystemTrigger bool `jsonschema:"Analysis result: Malicious Filesystem Trigger."`
}

func init() {
	aflow.Register[assessmentSecurityInputs, ai.AssessmentSecurityOutputs](
		ai.WorkflowAssessmentSecurity,
		"assess if a syzkaller bug is exploitable and what attack surfaces can reach it",
		&aflow.Flow{
			Root: aflow.Pipeline(
				actionsyzlang.CreateSimplifiedCRepro,
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:        "expert",
					Model:       aflow.BestExpensiveModel,
					Reply:       "ExplanationRaw",
					Outputs:     aflow.LLMOutputs[securityOutputs](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: securityInstruction,
					Prompt:      securityPrompt,
					Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
				},
				formatExplanation,
			),
		},
	)
}

const securityInstruction = `
You are an experienced Linux kernel security engineer. Your task is to analyze given kernel bug report
and determine its security impact based on the following dimensions.

Use the provided tools to examine the source code, check for capability checks (e.g., capable(), ns_capable()),
and understand the nature of the bug. Analyze the given kernel build and configuration.
You can check the kernel config by grepping ".config" file; you can check kernel cmdline by greeping
".config" file for "CONFIG_CMDLINE=". Assume sysctl parameters have default values.
But analyze for the corresponding production build w/o debugging tools enabled (like KASAN, KMSAN, UBSAN).

Don't make assumptions; verify them with source code access. Try different strategies when analyzing the bug:
 - think of ways in which the vulnerable code is unreachable
 - or the other way around: try to come up with different ideas of how an unprivileged user can reach the bug
If still unsure err on the side of the bug being non-exploitable/not-accessible.
In the final reply, provide a reasoning for your assessment.

Analysis dimensions:

* Exploitable:
Determine if the bug can result in memory corruption or elevated privileges.
Memory safety issues are almost always exploitable (KASAN or UBSAN reports for use-after-free, out-of-bounds;
refcounting issues, corrupted lists, etc). When kernel is crashing on a completly wild pointer access
(e.g. user-space address, or non-canonical address, but not on NULL or address corresponding to KASAN shadow
for NULL address), including both data accesses and control tranfers, that's also usually implies possibility
of exploitation. Such reports usually say "unable to handle kernel paging request".
Uses of uninitialized values detected by KMSAN may be exploitable b/c attacker frequently can affect uninit
values with spraying techniques. However, for these exploitabability depends on how exactly the uninit value
is used in the code, and what it affects.

Think of what happens after the bug is triggered. Some bugs cause kernel panic and halt execution,
they are harder to exploit. For example, BUG reports halts the kernel. However, WARNING reports don't halt
execution in production builds. Debug bug detection tools (like KASAN, KMSAN, KCSAN, UBSAN) are also not enabled
in production builds, so attacker can freely exploit these bugs w/o being detected by these tools.
If you see an integer overflow, think how the overflowed value used later (if it's used as allocation size,
or an array index). If you see an out-of-bounds read, think if it's followed by an out-of-bounds write as well.
Some KCSAN data-races may be exploitable by skilled attackers as well. Think what data structures got corrupted
as the result of data races and how. However, note that kernel has lots of "benign" data races that don't lead
to any runtime misbehavior at all.

* Denial Of Service:
Determine if the bug can result in denial-of-service. Most bugs can, since they cause system crash,
hangs, deadlocks, or resource leaks. This is mostly applicable to WARNING bugs that won't cause system crash
in production. For these think what will be consequences of the violation of the kernel assumptions flagged
by the WARNING. In some cases the unexpected condition is also properly handled by the normal control flow
(e.g. with "if (WARN_ON(...))"), these won't cause denial-of-service. If the condition is not handled,
then it may or may not cause denial-of-service.

* Accessible From Unprivileged Processes:
Determine if the bug can be reached from a typical (non-root) user process that does NOT have any special capabilities
(like CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_PERFMON) or access to device nodes restricted to root.
Assume that unprivileged_bpf_disabled=1, that is eBPF loading is not accessible. However, cBPF (classical BPF)
is still accessible to non-root processes.
Assume that user namespaces are not accessible, that is, the process cannot get the mentioned capabilities even
within a new user namespace (checked by ns_capable() function in the kernel sources).

* Accessible From User Namespaces:
Determine if the bug can be reached within a user-namespace where the process has all capabilities
(including CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_PERFMON). Such capabilities are checked with ns_capable()
function in the kernel sources.

* VM Guest Trigger:
Determine if the bug can be triggered from the context of a typical KVM guest (e.g., set up by a QEMU VMM).
Consider accesses to standard Linux host paravirtualized features (virtio-blk, virtio-net, etc.),
and handling of VM exits in the KVM code.

* VM Host Trigger in The Confidetial Computing Context:
Determine if the bug can be triggered in a confidential computing guest kernel from the context of a KVM host.
Consider access to standard Linux guest paravirtualized features (virtio-blk, virtio-net, etc.).

* Ethernet Network Trigger:
Determine if the bug can be triggered by processing ingress network Ethernet traffic, either directly (network stack)
or via drivers exposed to network data.

* Other Remote Trigger:
Determine if the bug can be triggered by processing remote traffic other than Ethernet (Wifi, Bluetooth, NFC, etc).

* Peripheral Trigger:
Determine if the bug can be triggered via an untrusted peripheral device that can be physically plugged
into a system, such as a USB device or a niche hardware driver handling external hardware inputs.
This is particularly important for mobile and desktop environments where users can plug in unknown devices.

* Malicious Filesystem Trigger:
Determine if the bug can be triggered by the kernel mounting and parsing a malicious filesystem image.
This is highly critical for Desktop and Mobile environments where external media or downloaded images
might be auto-mounted.
`

const securityPrompt = `
The kernel bug report is:

{{.CrashReport}}

{{if .SimplifiedCRepro}}

It is reproducible with the followint program.
Keep in mind that it may lack the precise threading, sandboxing, and some arguments of a working reproducer.
But it should give an idea of the involved syscalls.

{{.SimplifiedCRepro}}
{{end}}
`
