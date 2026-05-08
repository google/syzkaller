// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPopulateToolCalls_Basic verifies that a single tool call is correctly
// attributed to the immediately following LLM call at the same nesting level.
func TestPopulateToolCalls_Basic(t *testing.T) {
	spans := []*UIAITrajectorySpan{
		{Seq: 1, Nesting: 1, Type: "llm", Name: "agent"},
		{Seq: 2, Nesting: 1, Type: "tool", Name: "tool1"},
		{Seq: 3, Nesting: 1, Type: "llm", Name: "agent"},
	}

	PopulateToolCalls(spans)

	assert.Nil(t, spans[0].ToolCalls)
	assert.Nil(t, spans[1].ToolCalls)
	assert.Equal(t, []string{"tool1"}, spans[2].ToolCalls)
}

// TestPopulateToolCalls_MultipleTools verifies that multiple consecutive tool calls
// are accumulated and attributed together to the next LLM call.
func TestPopulateToolCalls_MultipleTools(t *testing.T) {
	spans := []*UIAITrajectorySpan{
		{Seq: 1, Nesting: 1, Type: "llm", Name: "agent"},
		{Seq: 2, Nesting: 1, Type: "tool", Name: "tool1"},
		{Seq: 3, Nesting: 1, Type: "tool", Name: "tool2"},
		{Seq: 4, Nesting: 1, Type: "llm", Name: "agent"},
	}

	PopulateToolCalls(spans)

	assert.Nil(t, spans[0].ToolCalls)
	assert.Nil(t, spans[1].ToolCalls)
	assert.Nil(t, spans[2].ToolCalls)
	assert.Equal(t, []string{"tool1", "tool2"}, spans[3].ToolCalls)
}

// TestPopulateToolCalls_NestedAgents verifies that in a complex trajectory with
// nested sub-agents (indicated by nesting level depth), tool calls are correctly
// isolated and attributed only to the next LLM call at the same nesting level,
// preventing sub-agent tool calls from leaking into the outer agent's tooltips.
func TestPopulateToolCalls_NestedAgents(t *testing.T) {
	spans := []*UIAITrajectorySpan{
		{Seq: 1, Nesting: 2, Type: "llm", Name: "smarty"},
		{Seq: 2, Nesting: 2, Type: "tool", Name: "researcher"},
		{Seq: 3, Nesting: 4, Type: "llm", Name: "researcher"},
		{Seq: 4, Nesting: 4, Type: "tool", Name: "researcher-tool"},
		{Seq: 5, Nesting: 4, Type: "llm", Name: "researcher"},
		{Seq: 6, Nesting: 2, Type: "llm", Name: "smarty"},
	}

	PopulateToolCalls(spans)

	assert.Nil(t, spans[0].ToolCalls)
	assert.Nil(t, spans[1].ToolCalls)
	assert.Nil(t, spans[2].ToolCalls) // Should not steal "researcher"
	assert.Nil(t, spans[3].ToolCalls)
	assert.Equal(t, []string{"researcher-tool"}, spans[4].ToolCalls)
	assert.Equal(t, []string{"researcher"}, spans[5].ToolCalls)
}
