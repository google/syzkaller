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
	Nesting  int
	Type     SpanType
	Name     string // flow/action/tool name
	Started  time.Time
	Finished time.Time
	Error    string // relevant if Finished is set

	// Args/results for actions/tools.
	Args    map[string]any
	Results map[string]any

	// Agent invocation.
	Instruction string
	Prompt      string
	Reply       string

	// LLM invocation.
	Thoughts string
}

type SpanType string

const (
	SpanFlow   = SpanType("flow") // always the first outermost span
	SpanAction = SpanType("action")
	SpanAgent  = SpanType("agent")
	SpanLLM    = SpanType("llm")
	SpanTool   = SpanType("tool")
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
			if span.Thoughts != "" {
				fmt.Fprintf(sb, "thoughts:\n%v\n", span.Thoughts)
			}
		case SpanTool:
			printMap(sb, span.Results, "results")
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
