// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/kernel"
)

// TODO: use cause bisection info, if available.
// TODO: try to cause bisect using LLM.

type Inputs struct {
	Title             string `json:"title"`
	Arch              string `json:"arch"`
	VMArch            string `json:"vm-arch"`
	ReproOpts         string `json:"repro-opts"`
	ReproSyz          string `json:"repro-syz"`
	ReproC            string `json:"repro-c" aflow:"-"`
	Report            string `json:"crash-report"`
	KernelRepo        string `json:"kernel-repo"`
	KernelCommit      string `json:"kernel-commit"`
	KernelConfig      string `json:"kernel-config" aflow:"-"`
	SyzkallerCommit   string `json:"syzkaller-commit"`
	CodesearchToolBin string `json:"codesearch-tool-bin"`
}

type Outputs struct {
	Subsystem    string `json:"kernel-subsystem"`
	Description  string `json:"patch-description"`
	Diff         string `json:"patch-diff"`
	KernelCommit string `json:"kernel-commit"`
}

func init() {
	tools := codesearcher.Tools

	aflow.Register[Inputs, Outputs](
		&aflow.Flow{
			Name:         "patching",
			Description:  "generate kernel patch fixing a provided bug report",
			MajorVersion: 1,
			MinorVersion: 1,
			Root: &aflow.Pipeline{
				Actions: []aflow.Action{
					// Checkout original source related to the crash,
					// so that tools can look at the source code.
					kernel.Checkout,
					&aflow.LLMAgent{
						Name:        "subsystem-identifier",
						OutputKey:   "kernel-subsystem",
						Temperature: 1,
						Instruction: subsystemInstruction,
						Prompt:      subsystemPrompt,
					},
					// Determine the right kernel tree for the fix.
					kernel.SubsystemToRepo,
					// Checkout and build the tree we will use for patch generation.
					kernel.Checkout,
					kernel.Build,
					// Ensure we can reproduce the crash (and the build boots).
					crash.Reproduce,
					codesearcher.PrepareIndex,
					&aflow.LLMAgent{
						Name:        "debugger",
						OutputKey:   "bug-explanation",
						Temperature: 1,
						Instruction: debuggingInstruction,
						Prompt:      debuggingPrompt,
						Tools:       tools,
					},
					&aflow.LLMAgent{
						Name:        "diff-generator",
						OutputKey:   "patch-diff",
						Temperature: 1,
						Instruction: diffInstruction,
						Prompt:      diffPrompt,
						Tools:       tools,
					},
					&aflow.LLMAgent{
						Name:        "description-generator",
						OutputKey:   "patch-description",
						Temperature: 1,
						Instruction: descriptionInstruction,
						Prompt:      descriptionPrompt,
					},
				},
			},
		},
	)
}

const subsystemInstruction = `
You are an experienced Linux kernel developer tasked with identifying the kernel subsystem
for a kernel bug. The subsystem will be later used to find the relevant kernel tree to
apply a fix for this bug, and to mail the fix to relevant kernel maintainers.
Your final reply should contain only the subsystem name.
You need to choose one of the following kernel subsystem names:
 - net
 - fs
 - usb
`

const subsystemPrompt = `
The crash that corresponds to the bug is:

{crash-report}
`

// TODO: mention not doing assumptions about the source code, and instead querying code using tools.
// TODO: mention to extensively use provided tools to confirm everything.

const debuggingInstruction = `
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation.
Your final reply must contain only the explanation.
`

const debuggingPrompt = `
The crash is:

{crash-report}

Call some codesearch tools first.
`

const diffInstruction = `
You are an experienced Linux kernel developer tasked with creating a patch for a kernel bug.
Your final reply should contain only the code diff in patch format.
`

const diffPrompt = `
The crash that corresponds to the bug is:

{crash-report}

The explanation of the root cause of the bug is:

{bug-explanation}
`

const descriptionInstruction = `
You are an experienced Linux kernel developer tasked with writing a commit description for
a kernel bug fixing commit. The description should start with a one-line summary,
and then include description of the bug being fixed, and how it's fixed by the provided patch.
Your final reply should contain only the text of the commit description.
`

const descriptionPrompt = `
The crash that corresponds to the bug is:

{crash-report}

The explanation of the root cause of the bug is:

{bug-explanation}

The diff of the bug fix is:

{patch-diff}
`
