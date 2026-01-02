// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessmenet

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

type KCSANOutputs struct {
	Benign      bool
	Explanation string
}

func init() {
	aflow.Register[Inputs, KCSANOutputs](
		ai.WorkflowAssessmentKCSAN,
		"assess if a KCSAN report is about a benign race that only needs annotations or not",
		&aflow.Flow{
			Root: &aflow.Pipeline{
				Actions: []aflow.Action{
					kernel.Checkout,
					kernel.Build,
					codesearcher.PrepareIndex,
					&aflow.LLMAgent{
						Name:  "expert",
						Reply: "Explanation",
						Outputs: aflow.LLMOutputs[struct {
							Benign bool `jsonschema:"If the data race is benign or not."`
						}](),
						Temperature: 1,
						Instruction: instruction,
						Prompt:      prompt,
						Tools:       codesearcher.Tools,
					},
				},
			},
		},
	)
}

const instruction = `
You are an experienced Linux kernel developer tasked with determining if the given kernel bug
report is actionable or not. Actionable means that it contains enough info to root cause
the underlying bug, and that the report is self-consistent and makes sense, rather than
a one-off nonsensical crash induced by a previous memory corruption.

Use the provided tools to confirm any assumptions, what variables/fields being accessed, etc.
In particular, don't make assumptions about the kernel source code,
use codesearch tools to read the actual source code.

The bug report is a data race report from KCSAN tool.
It contains 2 stack traces of the memory accesses that constitute a data race.
The report would be inconsistent, if the stacks point to different subsystems,
or if they access different fields.
The report would be non-actionable, if the underlysing data race is "benign".
That is, the race is on a simple int/bool or similar field, and the accesses
are not supposed to be protected by any mutual exclusion primitives.
Common examples of such "benign" data races are accesses to various flags fields,
statistics counters, and similar.
An actionable race is "harmful", that is can lead to corruption/crash even with
a conservative compiler that compiles memory accesses to primitive types
effectively as atomic. A common example of a "harmful" data races is race on
a complex container (list/hashmap/etc), where accesses are supposed to be protected
by a mutual exclusion primitive.
In the final reply explain why you think the report is consistent and the data race is harmful.
`

const prompt = `
The bug report is:

{{.CrashReport}}
`
