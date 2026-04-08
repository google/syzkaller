// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessmenet

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type kcsanInputs struct {
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

func init() {
	aflow.Register[kcsanInputs, ai.AssessmentKCSANOutputs](
		ai.WorkflowAssessmentKCSAN,
		"assess if a KCSAN report is about a benign race that only needs annotations or not",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:  "expert",
					Model: aflow.GoodBalancedModel,
					Reply: "Explanation",
					Outputs: aflow.LLMOutputs[struct {
						Benign bool `jsonschema:"If the data race is benign or not."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: kcsanInstruction,
					Prompt:      kcsanPrompt,
					Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
				},
				&aflow.LLMAgent{
					Name:  "skeptic",
					Model: aflow.GoodBalancedModel,
					Outputs: aflow.LLMOutputs[struct {
						Confident bool `jsonschema:"If the expert's analysis is correct and well-supported or not."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: kcsanSkepticInstruction,
					Prompt:      kcsanSkepticPrompt,
				},
			),
		},
	)
}

const kcsanInstruction = `
You are an experienced Linux kernel developer tasked with determining if the given kernel
data race is benign or not. The data race report is from KCSAN tool.
It contains 2 stack traces of the memory accesses that constitute a data race.

A "benign" data races are on a simple int/bool variable or similar field,
and the accesses are not supposed to be protected by any mutual exclusion primitives.
Common examples of such "benign" data races are accesses to various flags fields,
statistics counters, and similar. A "benign" data race does not lead to memory corruption/crash
with a conservative compiler that compiles memory accesses to primitive types
effectively as atomic.

A non-benign (or "harmful" data race) can lead to corruption/crash even with
a conservative compiler that compiles memory accesses to primitive types
effectively as atomic. A common example of a "harmful" data races is race on
a complex container (list/hashmap/etc), where accesses are supposed to be protected
by a mutual exclusion primitive.

Also consider races that happen at the same time with the given one.
If there is no synchronization in between, other memory accesses in the involved threads
race with each other if they access the same memory. For example, if both threads execute:

	some_struct->have_elements = true;
	list_add(new_node, &some_struct->list_head);

the race on some_struct->have_elements may appear benign, however it also implies there
is a race on some_struct->list_head which is not benign, since the list is not thread-safe.

Take into account that on 32-bit systems 64-bit memory accesses may be split into two accesses,
and thus even with a conservative compiler may not be fully atomic. However, such races may
still be benign depending on how writes are done, and how read data is used.

In the final reply explain why you think the given data race is benign or is harmful.

Use the provided tools to confirm any assumptions, variables/fields being accessed, etc.
In particular, don't make assumptions about the kernel source code,
use codesearch tools to read the actual source code.
`

const kcsanPrompt = `
The data race report is:

{{.CrashReport}}
`

const kcsanSkepticInstruction = `
You are reviewing a kernel developer's analysis of a KCSAN data race report.
You did NOT write this analysis. Evaluate it critically and independently.

Set Confident to true only if the reasoning is sound, the conclusion is clearly
supported by evidence, and there are no significant gaps or unverified assumptions.
Set Confident to false if there is meaningful doubt about the correctness of the verdict.
`

const kcsanSkepticPrompt = `
The original data race report:
{{.CrashReport}}

The expert concluded the race is {{if .Benign}}benign{{else}}not benign{{end}}.

Their explanation:
{{.Explanation}}

Is the conclusion well-supported? Are you confident in it?
`
