// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

// LLMTool acts like a tool for the parent LLM, but is itself implemented as an LLM agent.
// It can have own tools, different from the parent LLM agent.
// It can do complex multi-step research, and provide a concise answer to the parent LLM
// without polluting its context window.
type LLMTool struct {
	// Most fields match that of LLMAgent.
	// The prompt is not specified here, and is provided by the parent LLM.
	Name     string
	Model    backend.ModelCategory
	TaskType TaskType
	// Description of the tool exposed to the parent LLM.
	Description string
	Instruction string
	Tools       []Tool

	agent *LLMAgent
}

type llmToolArgs struct {
	Question string `jsonschema:"Question you have."`
}

type llmToolResults struct {
	Answer string `jsonschema:"Answer to your question."`
}

func (t *LLMTool) declaration() *backend.FunctionDeclaration {
	return &backend.FunctionDeclaration{
		Name:                 t.Name,
		Description:          t.Description,
		ParametersJSONSchema: mustSchemaFor[llmToolArgs](),
		ResponseJSONSchema:   mustSchemaFor[llmToolResults](),
	}
}

func (t *LLMTool) execute(ctx *Context, args map[string]any) (map[string]any, error) {
	a, err := convertFromMap[llmToolArgs](args, false, true)
	if err != nil {
		return nil, err
	}
	// We temporarily use ctx.state to provide the prompt to the agent,
	// and extract the reply.
	ctx.state[llmToolPrompt] = a.Question
	defer delete(ctx.state, llmToolPrompt)
	if err := t.agent.execute(ctx); err != nil {
		return nil, err
	}
	reply, ok := ctx.state[llmToolReply]
	if !ok {
		return nil, errors.New("state does not contain LLMTool reply")
	}
	delete(ctx.state, llmToolReply)
	return map[string]any{"Answer": reply}, nil
}

const (
	llmToolPrompt = "AFLOW_LLMTOOL_PROMPT"
	llmToolReply  = "AFLOW_LLMTOOL_REPLY"
)

func (t *LLMTool) verify(ctx *verifyContext) {
	t.agent = &LLMAgent{
		Name:        t.Name,
		Model:       t.Model,
		Reply:       llmToolReply,
		TaskType:    t.TaskType,
		Instruction: t.Instruction,
		Prompt:      fmt.Sprintf("{{.%v}}", llmToolPrompt),
		Tools:       t.Tools,
	}
	t.agent.verify(ctx)
}
