// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type assessmentSecurityInputs struct {
	CrashReport  string
	ReproSyz     string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

type securityOutputs struct {
	Exploitable       bool `jsonschema:"Likely exploitable for privilege escalation or memory corruption."`
	Unprivileged      bool `jsonschema:"Can be reached from a typical user process without special capabilities."`
	VMTrigger         bool `jsonschema:"Can be triggered from a typical Virtual Machine guest."`
	NetworkTrigger    bool `jsonschema:"Can be triggered from the network (e.g., via network protocols)."`
	PeripheralTrigger bool `jsonschema:"Can be triggered via a peripheral (e.g., USB or niche hardware)."`
}

func init() {
	aflow.Register[assessmentSecurityInputs, ai.AssessmentSecurityOutputs](
		ai.WorkflowAssessmentSecurity,
		"assess if a syzkaller bug is exploitable and what attack surfaces can reach it",
		&aflow.Flow{
			Root: aflow.Pipeline(
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
You are an experienced Linux kernel security researcher. Your task is to analyze a given kernel bug report
and determine its security impact based on the following dimensions:

1. Exploitable:
Determine if the bug can result in memory corruption or elevated privileges.
- Memory safety issues (KASAN reports like Use-After-Free, Out-Of-Bounds, etc.) are almost always exploitable.
- Refcounting issues or logic errors with severe consequences (e.g., in security-related code) are also exploitable.

2. Unprivileged:
Determine if the bug can be reached from a typical user process that does NOT have any special capabilities
(like CAP_SYS_ADMIN, CAP_NET_ADMIN) or access to device nodes restricted to root.
Consider various environments: Desktop, Mobile (Android), Cloud.

3. VM Trigger:
Determine if the bug can be triggered from the context of a typical KVM guest (e.g., set up by a QEMU VMM).
Consider access to standard Linux host paravirtualized features (virtio-blk, virtio-net, etc.).
A bug triggerable from a guest that affects the host kernel is highly significant.

4. Network Trigger:
Determine if the bug can be triggered by processing network traffic, either directly (network stack)
or via drivers exposed to network data.

5. Peripheral Trigger:
Determine if the bug can be triggered via an untrusted peripheral device that can be physically plugged
into a system, such as a USB device or a niche hardware driver handling external hardware inputs.
This is particularly important for mobile and desktop environments where users can plug in unknown devices.

In the final reply, provide a detailed reasoning for your assessment. Use the provided tools
to examine the source code, check for capability checks (e.g., capable(), ns_capable()),
and understand the nature of the bug. Don't make assumptions; verify them with source code access.
`

const securityPrompt = `
The kernel bug report is:

{{.CrashReport}}

{{if .ReproSyz}}
It is known to be reproducible with at least this syzkaller program:

{{.ReproSyz}}
{{end}}
`
