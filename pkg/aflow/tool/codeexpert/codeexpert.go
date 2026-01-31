// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeexpert

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
)

var Tool = &aflow.LLMTool{
	Name:        "codeexpert",
	Model:       aflow.GoodBalancedModel,
	TaskType:    aflow.FormalReasoningTask,
	Description: description,
	Instruction: instruction,
	Tools:       codesearcher.Tools,
}

const description = `
The tool can answer complex questions about kernel source code,
function behavior/pre-conditons/post-conditions, structs and their fields,
assess vality of code snippets, verify various hypothesis, etc.
It has access to more sources of information than you, use it to answer
particularly complex questions that require lots of research, and looking
at lots of data, and have a concrete concise answer.

Formulate your question as concretly as possible, include concrete
function/struct/field/variable names, line numbers, etc.
Formulate what exactly you want to see in the answer and in what form.
`

const instruction = `
You are a capable Linux kernel developer tasked with researching complex questions
about kernel source code. You will be given a concrete question, and need to provide
a concrete answer.
Use tools extensively while researching the question. Don't make assumptions,
or rely on your previous knowledge about the kernel source code, use available tools
to access the actual source code.
Use all available sources of information:
 - kernel source code
 - documentation in the Documentation dir in the source tree
 - git commits descriptions, git blame
`
