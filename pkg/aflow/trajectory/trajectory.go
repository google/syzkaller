// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package trajectory

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Span describes one step in an aflow workflow execution.
// Spans can be finished/unfinished (Finished field), and nested (Nesting field).
type Span struct {
	// Seq is monotomically increasing for each new span in a workflow starting from 0.
	Seq int
	// Nesting represents hierarchical relation between spans.
	// For example, SpanTool spans within SpanAgent have +1 nesting level.
	Nesting int
	Type    SpanType
	Name    string // flow/action/tool name
	// LLM model name for agent/LLM spans.
	Model    string `json:",omitzero"`
	Started  time.Time
	Finished time.Time `json:",omitzero"`
	// Relevant if Finished is set.
	Error string `json:",omitzero"`

	// Args/results for actions/tools.
	Args    map[string]any `json:",omitzero"`
	Results map[string]any `json:",omitzero"`

	// Agent invocation.
	Instruction string `json:",omitzero"`
	Prompt      string `json:",omitzero"`
	Reply       string `json:",omitzero"`

	// LLM invocation.
	Thoughts string `json:",omitzero"`

	// For details see:
	// https://pkg.go.dev/google.golang.org/genai#GenerateContentResponseUsageMetadata
	InputTokens          int `json:",omitzero"`
	OutputTokens         int `json:",omitzero"`
	OutputThoughtsTokens int `json:",omitzero"`
}

type SpanType string

// Note: don't change string values of these consts w/o a good reason.
// They are stored in the dashboard database as strings.
const (
	SpanFlow   = SpanType("flow") // always the first outermost span
	SpanAction = SpanType("action")
	SpanAgent  = SpanType("agent")
	SpanLLM    = SpanType("llm")
	SpanTool   = SpanType("tool")
	// Logical grouping of several invocations of the same agent.
	SpanAgentCandidates = SpanType("agent-candidates")
	SpanLoop            = SpanType("loop")
	SpanLoopIteration   = SpanType("iteration")
)

func (span *Span) String() string {
	// This is used for console logging only.
	sb := new(strings.Builder)
	if span.Finished.IsZero() {
		fmt.Fprintf(sb, "starting %v %v (%v/%v)...\n",
			span.Type, span.Name, span.Nesting, span.Seq)
		switch span.Type {
		case SpanFlow:
		case SpanAction:
		case SpanAgent:
			fmt.Fprintf(sb, "instruction:\n%v\nprompt:\n%v\n", span.Instruction, span.Prompt)
		case SpanLLM:
		case SpanTool:
			printMap(sb, span.Args, "args")
		case SpanLoop:
		case SpanLoopIteration:
		default:
			panic(fmt.Sprintf("unhandled span type %v", span.Type))
		}
	} else {
		fmt.Fprintf(sb, "finished %v %v (%v/%v) in %v\n",
			span.Type, span.Name, span.Nesting, span.Seq, span.Finished.Sub(span.Started))
		switch span.Type {
		case SpanFlow:
			printMap(sb, span.Results, "results")
		case SpanAction:
			printMap(sb, span.Results, "results")
		case SpanAgent:
			if span.Results != nil {
				printMap(sb, span.Results, "results")
			}
			fmt.Fprintf(sb, "reply:\n%v\n", span.Reply)
		case SpanLLM:
			fmt.Fprintf(sb, "tokens: input=%v output=%v thoughts=%v\n",
				span.InputTokens, span.OutputTokens, span.OutputThoughtsTokens)
			if span.Thoughts != "" {
				fmt.Fprintf(sb, "thoughts:\n%v\n", span.Thoughts)
			}
		case SpanTool:
			printMap(sb, span.Results, "results")
		case SpanLoop:
		case SpanLoopIteration:
		default:
			panic(fmt.Sprintf("unhandled span type %v", span.Type))
		}
	}
	if span.Error != "" {
		fmt.Fprintf(sb, "error:\n%v\n", span.Error)
	}
	return sb.String()
}

func printMap(sb *strings.Builder, m map[string]any, what string) {
	fmt.Fprintf(sb, "%v:\n", what)
	type nameVal struct {
		name string
		val  any
	}
	var sorted []nameVal
	for k, v := range m {
		sorted = append(sorted, nameVal{k, v})
	}
	slices.SortFunc(sorted, func(a, b nameVal) int {
		return strings.Compare(a.name, b.name)
	})
	for _, kv := range sorted {
		fmt.Fprintf(sb, "\t%v: %v\n", kv.name, kv.val)
	}
}
