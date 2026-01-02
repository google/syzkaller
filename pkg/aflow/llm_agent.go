// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
	"google.golang.org/genai"
)

type LLMAgent struct {
	// For logging/debugging.
	Name string
	// Name of the state variable to store the final reply of the agent.
	// These names can be used in subsequent action instructions/prompts,
	// and as final workflow outputs.
	Reply   string
	Outputs *llmOutputs
	// Value that controls the degree of randomness in token selection.
	// Lower temperatures are good for prompts that require a less open-ended or creative response,
	// while higher temperatures can lead to more diverse or creative results.
	// Must be assigned a float32 value in the range [0, 2].
	Temperature any
	// Instructions for the agent.
	// Formatted as text/template, can use "{{.Variable}}" as placeholders for dynamic content.
	// Variables can come from the workflow inputs, or from preceding actions outputs.
	Instruction string
	// Prompt for the agent. The same format as Instruction.
	Prompt string
	// Set of tools for the agent to use.
	Tools []Tool
}

func LLMOutputs[Args any]() *llmOutputs {
	return &llmOutputs{
		createTool: func(a *llmAgentInstance) tool.Tool {
			cfg := functiontool.Config{
				Name:        "set-results",
				Description: "Use this tool to provide results of the analysis.",
			}
			tool, err := functiontool.New(cfg, func(ctx tool.Context, args Args) (struct{}, error) {
				if a.outputs != nil {
					return struct{}{}, fmt.Errorf("set-results tool is called more than once")
				}
				a.outputs = convertToMap(args)
				return struct{}{}, nil
			})
			if err != nil {
				panic(err)
			}
			return tool
		},
		verify: func(vctx *verifyContext, who string) {
			requireJsonSchema[Args](vctx, who, "Outputs")
			provideOutputs[Args](vctx, who)
		},
	}
}

type llmAgentInstance struct {
	meta        *LLMAgent
	name        string
	agentSpan   *trajectory.Span
	requestSpan *trajectory.Span
	request     []*genai.Content
	lastResp    *model.LLMResponse
	outputs     map[string]any
}

type llmOutputs struct {
	createTool func(*llmAgentInstance) tool.Tool
	verify     func(*verifyContext, string)
}

func (meta *LLMAgent) create(cctx *createContext) (agent.Agent, error) {
	a := &llmAgentInstance{
		meta: meta,
		name: cctx.actionName(meta.Name, ""),
	}
	var tools []tool.Tool
	if meta.Outputs != nil {
		tools = append(tools, meta.Outputs.createTool(a))
	}
	for _, t := range meta.Tools {
		tool, err := t.create(cctx)
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return llmagent.New(llmagent.Config{
		Name:                     a.name,
		GenerateContentConfig:    cctx.contentConfig,
		Model:                    cctx.llm,
		IncludeContents:          llmagent.IncludeContentsNone,
		Tools:                    tools,
		OutputKey:                meta.Reply,
		DisallowTransferToParent: true,
		DisallowTransferToPeers:  true,
		BeforeAgentCallbacks:     []agent.BeforeAgentCallback{a.beforeAgent},
		AfterAgentCallbacks:      []agent.AfterAgentCallback{a.afterAgent},
		BeforeModelCallbacks:     []llmagent.BeforeModelCallback{a.beforeModel},
		AfterModelCallbacks:      []llmagent.AfterModelCallback{a.afterModel},
		BeforeToolCallbacks:      []llmagent.BeforeToolCallback{a.beforeTool},
		AfterToolCallbacks:       []llmagent.AfterToolCallback{a.afterTool},
	})
}

func (meta *LLMAgent) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(meta.Name, "Name", meta.Name)
	vctx.requireNotEmpty(meta.Name, "Reply", meta.Reply)
	if temp, ok := meta.Temperature.(int); ok {
		meta.Temperature = float32(temp)
	}
	if temp, ok := meta.Temperature.(float32); !ok || temp < 0 || temp > 2 {
		vctx.errorf(meta.Name, "Temperature must have a float32 value in the range [0, 2]")
	}
	// Verify dataflow. All dynamic variables must be provided by inputs,
	// or preceding actions.
	meta.verifyTemplate(vctx, "Instruction", meta.Instruction)
	meta.verifyTemplate(vctx, "Prompt", meta.Prompt)
	for _, tool := range meta.Tools {
		tool.verify(vctx)
	}
	vctx.provideOutput(meta.Name, meta.Reply, reflect.TypeFor[string](), true)
	if meta.Outputs != nil {
		meta.Outputs.verify(vctx, meta.Name)
	}
}

func (meta *LLMAgent) verifyTemplate(vctx *verifyContext, what, text string) {
	vctx.requireNotEmpty(meta.Name, what, text)
	vars := make(map[string]reflect.Type)
	for name, state := range vctx.state {
		vars[name] = state.typ
	}
	used, err := verifyTemplate(text, vars)
	if err != nil {
		vctx.errorf(meta.Name, "%v: %v", what, err)
	}
	for name := range used {
		vctx.state[name].used = true
	}
}

func (a *llmAgentInstance) beforeAgent(cctx agent.CallbackContext) (*genai.Content, error) {
	ctx := cctx.Value(contextKey).(*Context)
	instruction := formatPrompt(a.meta.Instruction, ctx.state)
	if a.meta.Outputs != nil {
		instruction += `
Use set-results tool to provide results of the analysis.
It must be called exactly once before the final reply.
`
	}
	a.agentSpan = &trajectory.Span{
		Type:        trajectory.SpanAgent,
		Name:        a.name,
		Instruction: instruction,
		Prompt:      formatPrompt(a.meta.Prompt, ctx.state),
	}
	if err := ctx.startSpan(a.agentSpan); err != nil {
		return nil, err
	}
	a.request = []*genai.Content{genai.NewContentFromText(a.agentSpan.Prompt, genai.RoleUser)}
	return nil, nil
}

func (a *llmAgentInstance) afterAgent(cctx agent.CallbackContext) (*genai.Content, error) {
	resp, span := a.lastResp, a.agentSpan
	a.lastResp, a.agentSpan = nil, nil
	if resp == nil {
		return nil, nil
	}
	if a.meta.Outputs != nil && a.outputs == nil {
		return nil, fmt.Errorf("set-results tool was not called")
	}
	ctx := cctx.Value(contextKey).(*Context)
	// Check that we don't get something unexpected.
	// If these assumptions break, it does not necessarily mean a bug,
	// we just need to understand the meaning and how to handle these cases.
	if resp.Partial || resp.Interrupted ||
		resp.CitationMetadata != nil || resp.GroundingMetadata != nil ||
		resp.LogprobsResult != nil {
		panic(fmt.Sprintf("unexpected event data: %+v", *resp))
	}
	for _, part := range resp.Content.Parts {
		if part.VideoMetadata != nil || part.InlineData != nil || part.FileData != nil ||
			part.FunctionCall != nil || part.FunctionResponse != nil ||
			part.CodeExecutionResult != nil || part.ExecutableCode != nil {
			panic(fmt.Sprintf("unexpected part data: %+v", *part))
		}
		if !part.Thought {
			span.Reply += part.Text
		}
	}
	span.Results = a.outputs
	ctx.state[a.meta.Reply] = span.Reply
	maps.Insert(ctx.state, maps.All(a.outputs))
	if err := ctx.finishSpan(span, nil); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *llmAgentInstance) beforeModel(cctx agent.CallbackContext, req *model.LLMRequest) (*model.LLMResponse, error) {
	ctx := cctx.Value(contextKey).(*Context)
	a.requestSpan = &trajectory.Span{
		Type: trajectory.SpanLLM,
		Name: a.name,
	}
	if err := ctx.startSpan(a.requestSpan); err != nil {
		return nil, err
	}
	req.Config.SystemInstruction = genai.NewContentFromText(a.agentSpan.Instruction, genai.RoleUser)
	req.Config.Temperature = genai.Ptr(a.meta.Temperature.(float32))
	req.Contents = a.request
	return nil, nil
}

func (a *llmAgentInstance) afterModel(cctx agent.CallbackContext, resp *model.LLMResponse, llmError error) (
	*model.LLMResponse, error) {
	ctx := cctx.Value(contextKey).(*Context)
	a.lastResp = resp
	span := a.requestSpan
	a.requestSpan = nil
	if resp != nil {
		a.request = append(a.request, resp.Content)
		for _, part := range resp.Content.Parts {
			if part.Thought {
				span.Thoughts += part.Text
			}
		}
	}
	err := ctx.finishSpan(span, llmError)
	return resp, err
}

func (a *llmAgentInstance) beforeTool(tctx tool.Context, tool tool.Tool, args map[string]any) (map[string]any, error) {
	return nil, nil
}

func (a *llmAgentInstance) afterTool(tctx tool.Context, tool tool.Tool, args, result map[string]any, toolErr error) (
	map[string]any, error) {
	content := genai.NewContentFromFunctionResponse(tool.Name(), result, genai.RoleUser)
	content.Parts[0].FunctionResponse.ID = tctx.FunctionCallID()
	a.request = append(a.request, content)
	return result, toolErr
}

func verifyTemplate(text string, vars map[string]reflect.Type) (map[string]bool, error) {
	templ, err := parseTemplate(text)
	if err != nil {
		return nil, err
	}
	used := make(map[string]bool)
	walkTemplate(templ.Root, used, &err)
	if err != nil {
		return nil, err
	}
	vals := make(map[string]any)
	for name := range used {
		typ, ok := vars[name]
		if !ok {
			return nil, fmt.Errorf("input %v is not defined", name)
		}
		vals[name] = reflect.Zero(typ).Interface()
	}
	if err := templ.Execute(io.Discard, vals); err != nil {
		return nil, err
	}
	return used, nil
}

func walkTemplate(n parse.Node, used map[string]bool, errp *error) {
	if reflect.ValueOf(n).IsNil() {
		return
	}
	switch n := n.(type) {
	case *parse.ListNode:
		for _, c := range n.Nodes {
			walkTemplate(c, used, errp)
		}
	case *parse.IfNode:
		walkTemplate(n.Pipe, used, errp)
		walkTemplate(n.List, used, errp)
		walkTemplate(n.ElseList, used, errp)
	case *parse.ActionNode:
		walkTemplate(n.Pipe, used, errp)
	case *parse.PipeNode:
		for _, c := range n.Decl {
			walkTemplate(c, used, errp)
		}
		for _, c := range n.Cmds {
			walkTemplate(c, used, errp)
		}
	case *parse.CommandNode:
		for _, c := range n.Args {
			walkTemplate(c, used, errp)
		}
	case *parse.FieldNode:
		if len(n.Ident) != 1 {
			noteError(errp, "compound values are not supported: .%v", strings.Join(n.Ident, "."))
		}
		used[n.Ident[0]] = true
	case *parse.VariableNode:
	case *parse.TextNode:
	default:
		noteError(errp, "unhandled node type %T", n)
	}
}

func formatPrompt(text string, state map[string]any) string {
	templ, err := parseTemplate(text)
	if err != nil {
		panic(err)
	}
	w := new(bytes.Buffer)
	if err := templ.Execute(w, state); err != nil {
		panic(err)
	}
	return w.String()
}

func parseTemplate(prompt string) (*template.Template, error) {
	return template.New("").Option("missingkey=error").Parse(prompt)
}
