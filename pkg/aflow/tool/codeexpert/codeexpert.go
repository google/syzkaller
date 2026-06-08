// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeexpert

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/gitlog"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

var Tool = &aflow.LLMTool{
	Name:        "codeexpert",
	Model:       aflow.GoodBalancedModel,
	TaskType:    aflow.FormalReasoningTask,
	Description: description,
	Instruction: instruction,
	Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool, gitlog.Tools),
}

const description = `
The tool can answer complex questions about kernel source code,
function behavior/pre-conditons/post-conditions, structs and their fields,
assess vality of code snippets, verify various hypothesis, etc.
It has access to more sources of information than you, use it to answer
particularly complex questions that require lots of research, and looking
at lots of data, and have a concrete concise answer.

DO NOT use this tool for simple file reading, searching, or extracting line numbers.
Use other tools provided to you for those purposes.
Only use this tool for complex architectural or behavioral reasoning.

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

Do not guess file names or file paths and attempt to read them without
verifying their existence first using content search or directory listing tools.
If a file, symbol, or directory is not found via content search ('grepper') or
directory listing ('codesearch-dir-index'), treat it as completely absent.
Do not attempt to guess alternative names, extensions, or directories.
Do NOT use 'git-log' to search for the presence or existence of files in the
repository. 'git-log' is only for tracing commit history of files that are
already present in the current checkout. If a file does not exist in the
current checkout, it cannot be used for reproduction.

Avoid running broad 'git-log' queries (such as searches on the entire repo)
without a specific 'PathPrefix' to restrict the scope, as these are very
expensive and will time out.
If a 'git-log' tool call times out, do not retry the query with the same broad
scope. You must specify a tighter, narrower 'PathPrefix' for subsequent queries.
`
