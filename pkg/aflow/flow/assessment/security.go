// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type assessmentSecurityInputs struct {
	TargetOS     string
	TargetArch   string
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
	VMHostTrigger     bool `jsonschema:"Analysis result: VM Host Trigger in The Confidential Computing Context."`
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
					Instruction: common.Prompt(prompts, "prompts/security_instruction.md"),
					Prompt:      securityPrompt,
					Tools:       common.CodeAccessTools,
				},
				formatExplanation,
			),
		},
	)
}

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
