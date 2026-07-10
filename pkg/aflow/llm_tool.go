// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

// StructuredLLMTool acts like a tool for the parent LLM, but is itself implemented as an LLM agent.
// It can have own tools, different from the parent LLM agent.
// It can do complex multi-step research, and provide a concise answer to the parent LLM
// without polluting its context window.
type StructuredLLMTool[State, Args, Results any] struct {
	// Most fields match that of LLMAgent.
	Name     string
	Model    backend.ModelCategory
	TaskType TaskType
	// Description of the tool exposed to the parent LLM.
	Description string
	Instruction string
	Tools       []Tool

	// Prompt template for the subagent, formatted using both State and Args.
	Prompt string

	// PreExecute is run before prompt template execution. It returns additional variables
	// to merge into the template formatting context.
	PreExecute func(ctx *Context, state State, args Args) (map[string]any, error)

	// ExtraVars declares the types of extra template variables returned by PreExecute (for verification).
	ExtraVars map[string]reflect.Type

	// Optional structured outputs configuration for the subagent.
	// Use LLMOutputs or ValidatedLLMOutputs/ValidatedLLMToolOutputs functions to create it.
	Outputs *llmOutputs

	// Optional evaluator/judge agent that is invoked after each iteration to inspect history.
	Judge *LLMJudge

	agent *LLMAgent
}

type DefaultLLMArgs struct {
	Question string `jsonschema:"Question you have."`
}

// StringLLMToolResult is the standardized result for unstructured text answers.
type StringLLMToolResult struct {
	Answer string `jsonschema:"Answer to your question."`
}

// LLMTool is a generic type alias that maps to StructuredLLMTool natively.
type LLMTool[State, Args any] = StructuredLLMTool[State, Args, StringLLMToolResult]

func (t *StructuredLLMTool[State, Args, Results]) declaration() *backend.FunctionDeclaration {
	return &backend.FunctionDeclaration{
		Name:                 t.Name,
		Description:          t.Description,
		ParametersJSONSchema: mustSchemaFor[Args](),
		ResponseJSONSchema:   mustSchemaFor[Results](),
	}
}

func (t *StructuredLLMTool[State, Args, Results]) execute(ctx *Context, args map[string]any) (map[string]any, error) {
	s, err := convertFromMap[State](ctx.state, false, true)
	if err != nil {
		return nil, err
	}
	a, err := convertFromMap[Args](args, false, true)
	if err != nil {
		return nil, err
	}

	combined := make(map[string]any)
	maps.Copy(combined, convertToMap(s))
	maps.Copy(combined, convertToMap(a))
	for _, tool := range t.Tools {
		name := tool.declaration().Name
		combined[toolTemplateName(name)] = name
	}

	if t.PreExecute != nil {
		extras, err := t.PreExecute(ctx, s, a)
		if err != nil {
			return nil, err
		}
		maps.Copy(combined, extras)
	}

	prompt := formatTemplate(t.Prompt, combined)

	// Create a scoped sub-state for the sub-agent.
	// It inherits all parent state variables, but any mutations made by
	// the sub-agent will remain isolated in this map.
	subState := make(map[string]any, len(ctx.state)+2)
	maps.Copy(subState, ctx.state)
	subState[llmToolPrompt] = prompt
	subState[llmToolArgs] = a

	// Execute the sub-agent using the scoped state.
	err = ctx.runWithState(subState, func(ctx *Context) error {
		return t.agent.execute(ctx)
	})
	if err != nil {
		return nil, err
	}

	// Extract the generated results cleanly using type conversion.
	res, err := convertFromMap[Results](subState, false, true)
	if err != nil {
		return nil, err
	}
	return convertToMap(res), nil
}

const (
	llmToolPrompt = "AFLOW_LLMTOOL_PROMPT"
	llmToolReply  = "AFLOW_LLMTOOL_REPLY"
	llmToolArgs   = "AFLOW_LLMTOOL_ARGS"
)

func (t *StructuredLLMTool[State, Args, Results]) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(t.Name, "Name", t.Name)
	ctx.requireNotEmpty(t.Name, "Description", t.Description)
	requireSchema[Args](ctx, t.Name, "Args")
	requireSchema[Results](ctx, t.Name, "Results")
	requireInputs[State](ctx, t.Name)

	vars := make(map[string]reflect.Type)
	maps.Insert(vars, foreachFieldOf[State]())
	maps.Insert(vars, foreachFieldOf[Args]())
	maps.Copy(vars, t.ExtraVars)
	for _, tool := range t.Tools {
		vars[toolTemplateName(tool.declaration().Name)] = reflect.TypeFor[string]()
	}
	if _, err := verifyTemplate(t.Prompt, vars); err != nil {
		ctx.errorf(t.Name, "invalid prompt template: %v", err)
	}

	t.agent = &LLMAgent{
		Name:        t.Name,
		Model:       t.Model,
		TaskType:    t.TaskType,
		Instruction: t.Instruction,
		Prompt:      fmt.Sprintf("{{.%v}}", llmToolPrompt),
		Tools:       t.Tools,
		SubAgent:    true,
		Judge:       t.Judge,
	}

	if t.Outputs != nil {
		t.agent.Outputs = t.Outputs
	} else {
		t.agent.Outputs = LLMOutputs[Results]()
	}

	// We verify the sub-agent with outputs disabled so that its internal tools
	// (like set-results) do not register their outputs (e.g. Results fields) into
	// the parent flow's state. Otherwise, the parent flow would falsely report
	// them as unused outputs.
	oldOutputs := ctx.outputs
	ctx.outputs = false
	t.agent.verify(ctx)
	ctx.outputs = oldOutputs
}

// ValidatedLLMToolOutputs creates an *llmOutputs for StructuredLLMTool whose validation callback requires tool Args.
func ValidatedLLMToolOutputs[Results, State, Args any](
	validate func(*Context, State, Args, Results) (Results, error),
) *llmOutputs {
	return ValidatedLLMOutputs[Results, State](func(ctx *Context, state State, res Results) (Results, error) {
		a, _ := ctx.state[llmToolArgs].(Args)
		return validate(ctx, state, a, res)
	})
}
