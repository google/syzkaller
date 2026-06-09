package seedgen

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/flow/common"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

type AnalyzerQuery struct {
	Query string `jsonschema:"The specific research task or question."`
}

var SeedgenAnalyzer = aflow.LLMTool[struct{}, AnalyzerQuery]{
	Name: "seedgen-analyzer",
	Description: "Use this tool to explore the codebase. Provide a specific query, " +
		"and it will search the codebase and return a concise summary of the findings.",
	Model:    aflow.Temporary35FlashOnlyModel,
	TaskType: aflow.FormalReasoningTask,
	Tools: aflow.Tools(
		codesearcher.Tools,
		grepper.Tool,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
	),
	Instruction: "You are a strict codebase researcher. Your task is to execute the exact " +
		"research plan requested in the query.\n" +
		"There are two distinct domains you might need to research, with specific tools for each:\n" +
		"1. Linux Kernel Source Tree: Use 'codesearch-*' tools and 'grepper' to find struct layouts, macro definitions, " +
		"and function implementations in the target kernel. IMPORTANT: These tools search the Linux kernel ONLY.\n" +
		"2. Syzkaller Repository: Use the 'read-syz-spec' and 'syz-grepper' tools to read syzlang " +
		"descriptions (sys.txt files), test seeds, and syzkaller executor code (executor/). " +
		"DO NOT try to use codesearch or grepper for syzkaller files. " +
		"Note that test seeds are syzlang programs that establish preconditions, they do NOT contain kernel C code.\n" +
		"You are strongly encouraged to call multiple tools at once to speed up the research process. " +
		"For example, you can dispatch multiple code searches or grep commands in a single turn.\n" +
		"Do NOT attempt to write or execute seeds (aka c or syzlang programs).\n" +
		"Once you have found the necessary information, return a clean, concise and very detailed summary of the findings " +
		"in your final reply. (CRITICAL INSTRUCTION) Include all information you deem useful." +
		common.InstructionDontMakeAssumptionsAboutSourceCode,
	Prompt: "Query: {{.Query}}",
}
