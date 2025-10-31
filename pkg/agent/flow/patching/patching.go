// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"github.com/google/syzkaller/pkg/agent"
	"github.com/google/syzkaller/pkg/agent/tool/codesearch"
)

type Inputs struct {
	Title      string `json:"title"`
	Reproducer string `json:"reproducer"`
	Crash      string `json:"crash"`
}

type Outputs struct {
	Subsystem   string `json:"subsystem"`
	Description string `json:"description"`
	Diff        string `json:"diff"`
}

func init() {
	agent.Register[Inputs, Outputs](
		&agent.Flow{
			Name:         "patching",
			MajorVersion: 1,
			MinorVersion: 1,
			Root: &agent.SequentialAgent{
				Agents: []agent.Agent{
					&agent.LLMAgent{
						Name:        "debugger",
						OutputKey:   "explanation",
						Instruction: debuggingInstruction,
						Prompt:      debuggingPrompt,
						Tools:       []agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:        "subsystem-identifier",
						OutputKey:   "out:subsystem",
						Instruction: subsystemInstruction,
						Prompt:      subsystemPrompt,
						Tools:       []agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:        "diff-generator",
						OutputKey:   "out:diff",
						Instruction: diffInstruction,
						Prompt:      diffPrompt,
						Tools:       []agent.Tool{codesearch.Tool},
					},
					&agent.LLMAgent{
						Name:        "description-generator",
						OutputKey:   "out:description",
						Instruction: descriptionInstruction,
						Prompt:      descriptionPrompt,
					},
				},
			},
		},
	)
}

const debuggingInstruction = `
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation.
Your final reply must contain only the explanation.
`

const debuggingPrompt = `
The crash is:

{in:crash}
`

const subsystemInstruction = `
You are an experienced Linux kernel developer tasked with identifying the kernel subsystem
for a kernel bug. The subsystem will be later used to find the relevant kernel tree to
apply a fix for this bug, and to mail the fix to relevant kernel maintainers.
Your final reply should contain only the subsystem name.
You need to choose on of the following kernel subsystem names:
 - net
 - fs
 - usb
`

const subsystemPrompt = `
The crash that corresponds to the bug is:

{in:crash}

The explanation of the root cause of the bug is:

{explanation}
`

const diffInstruction = `
You are an experienced Linux kernel developer tasked with creating a patch for a kernel bug.
Your final reply should contain only the code diff in patch format.
`

const diffPrompt = `
The crash that corresponds to the bug is:

{in:crash}

The explanation of the root cause of the bug is:

{explanation}
`

const descriptionInstruction = `
You are an experienced Linux kernel developer tasked with writing a commit description for
a kernel bug fixing commit. The description should start with a one-line summary,
and then include description of the bug being fixed, and how it's fixed by the provided patch.
Your final reply should contain only the text of the commit description.
`

const descriptionPrompt = `
The crash that corresponds to the bug is:

{in:crash}

The explanation of the root cause of the bug is:

{explanation}

The diff of the bug fix is:

{out:diff}
`
