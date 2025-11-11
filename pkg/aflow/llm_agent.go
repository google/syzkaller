// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/aflow/journal"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/genai"
)

type LLMAgent struct {
	// For logging/debugging.
	Name string
	// Name of the session state variable to store the final reply of the agent.
	// These names can be used in subsequent action instructions/prompts.
	OutputKey string
	// Instructions for the agent. Can use "{variable}" as placeholders for dynamic content.
	// Variables can come from the workflow inputs, or from preceeding actions outputs.
	Instruction string
	// Prompt for the agent. Can use variables for dynamic content as well.
	Prompt string
	// Set of tools for the agent to use.
	Tools []Tool
}

type llmAgentInstance struct {
	meta *LLMAgent
	name string
	resp *model.LLMResponse
}

func (meta *LLMAgent) create(cctx *createContext) (agent.Agent, error) {
	a := &llmAgentInstance{
		meta: meta,
		name: cctx.actionName(meta.Name, ""),
	}
	var tools []tool.Tool
	for _, t := range meta.Tools {
		tool, err := t.create(cctx)
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return llmagent.New(llmagent.Config{
		Name:                     a.name,
		BeforeAgentCallbacks:     []agent.BeforeAgentCallback{a.beforeAgent},
		AfterAgentCallbacks:      []agent.AfterAgentCallback{a.afterAgent},
		GenerateContentConfig:    cctx.contentConfig,
		Model:                    cctx.llm,
		Instruction:              meta.Instruction,
		IncludeContents:          llmagent.IncludeContentsNone,
		BeforeModelCallbacks:     []llmagent.BeforeModelCallback{a.beforeModel},
		AfterModelCallbacks:      []llmagent.AfterModelCallback{a.afterModel},
		Tools:                    tools,
		OutputKey:                meta.OutputKey,
		DisallowTransferToParent: true,
		DisallowTransferToPeers:  true,
	})
}

func (meta *LLMAgent) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(meta.Name, "Name", meta.Name)
	vctx.requireNotEmpty(meta.Name, "Instruction", meta.Instruction)
	vctx.requireNotEmpty(meta.Name, "Prompt", meta.Prompt)
	vctx.requireNotEmpty(meta.Name, "OutputKey", meta.OutputKey)
	// Verify dataflow. All dynamic variables must be provided by inputs,
	// or preceeding actions.
	for _, name := range promptPlaceholderRe.FindAllStringSubmatch(meta.Instruction, -1) {
		vctx.requireInput(meta.Name, name[1])
	}
	for _, name := range promptPlaceholderRe.FindAllStringSubmatch(meta.Prompt, -1) {
		vctx.requireInput(meta.Name, name[1])
	}
	vctx.provideOutput(meta.Name, meta.OutputKey, true)
}

func (a *llmAgentInstance) beforeAgent(cctx agent.CallbackContext) (*genai.Content, error) {
	ctx := cctx.Value(contextKey).(*Context)
	span, err := ctx.journal.Append(&journal.EventAgentStart{
		SpanStart:   journal.SpanStart{Name: a.name},
		Instruction: formatPrompt(a.meta.Instruction, cctx.State()),
		Prompt:      formatPrompt(a.meta.Prompt, cctx.State()),
	})
	if err != nil {
		return nil, err
	}
	if span.End != nil {
		//!!! ctx.journal.SkipCurrentSpan()
		content := genai.NewContentFromText(span.End.AgentEnd.Result, genai.RoleModel)
		return content, nil
	}
	return nil, nil
}

func (a *llmAgentInstance) afterAgent(ctx agent.CallbackContext /*, ev *session.Event, agentErr error*/) (*genai.Content, error) {
	if false {
		dump, _ := json.MarshalIndent(a.resp, "", "\t")
		fmt.Printf("event:\n%s\n", dump)
	}

	result, thoughts := "", ""
	if a.resp != nil {
		if !a.resp.TurnComplete {
			//return nil, nil
		}
		// Check that we don't get something unexpected.
		// If these assumptions break, it does not necessarily mean a bug,
		// we just need to understand the meaning and how to handle these cases.
		if a.resp.Partial || a.resp.Interrupted ||
			a.resp.CitationMetadata != nil || a.resp.GroundingMetadata != nil ||
			a.resp.LogprobsResult != nil {
			panic(fmt.Sprintf("unexpected event data: %+v", *a.resp))
		}

		for _, part := range a.resp.Content.Parts {
			if part.VideoMetadata != nil || part.InlineData != nil || part.FileData != nil ||
				part.FunctionCall != nil || part.FunctionResponse != nil ||
				part.CodeExecutionResult != nil || part.ExecutableCode != nil {
				panic(fmt.Sprintf("unexpected part data: %+v", *part))
			}
			if part.Thought {
				thoughts += part.Text
			} else {
				result += part.Text
			}
		}
	}
	_, err := ctx.Value(contextKey).(*Context).journal.Append(&journal.EventAgentEnd{
		Result:   result,
		Thoughts: thoughts,
	})
	return nil, err
}

func (a *llmAgentInstance) beforeModel(ctx agent.CallbackContext, req *model.LLMRequest) (*model.LLMResponse, error) {
	span, err := ctx.Value(contextKey).(*Context).journal.Append(&journal.EventLLMRequest{})
	if err != nil {
		return nil, err
	}
	if span.End != nil {
		//!!!
	}
	start := span.Parent.Start.AgentStart
	req.Config.SystemInstruction = genai.NewContentFromText(start.Instruction, genai.RoleUser)
	req.Contents = []*genai.Content{genai.NewContentFromText(start.Prompt, genai.RoleUser)}
	for _, preceeding := range span.Parent.Nested {
		if preceeding == span {
			break
		}
		switch {
		case preceeding.Start.LLMRequest != nil:
		case preceeding.Start.ToolCall != nil:
			call := preceeding.Start.ToolCall
			req.Contents = append(req.Contents,
				genai.NewContentFromFunctionCall(call.Name, call.Args, genai.RoleModel),
				genai.NewContentFromFunctionResponse(call.Name, preceeding.End.ToolResult.Results, genai.RoleUser),
			)
		default:
			panic(fmt.Sprintf("unexpected event type: %+v", *preceeding.Start))
		}
	}

	//dump, _ := json.MarshalIndent(req, "", "\t")
	//fmt.Printf("request:\n%s\n", dump)

	return nil, nil
}

func (a *llmAgentInstance) afterModel(ctx agent.CallbackContext, resp *model.LLMResponse, llmError error) (*model.LLMResponse, error) {
	a.resp = resp
	_, err := ctx.Value(contextKey).(*Context).journal.Append(&journal.EventLLMResponse{
		SpanEnd: journal.SpanEnd{
			Error: errorToString(llmError),
		},
	})
	if llmError != nil {
		err = llmError
	}
	return resp, err
}

var promptPlaceholderRe = regexp.MustCompile(`{+([^{}]*)}+`)

func formatPrompt(template string, state session.State) string {
	// Format the prompt the same way ADK does for instructions.
	var result strings.Builder
	last := 0
	for _, match := range promptPlaceholderRe.FindAllStringIndex(template, -1) {
		result.WriteString(template[last:match[0]])
		last = match[1]
		name := strings.TrimSpace(strings.Trim(template[match[0]:match[1]], "{}"))
		value, err := state.Get(name)
		if err != nil {
			panic(err)
		}
		result.WriteString(fmt.Sprint(value))
	}
	result.WriteString(template[last:])
	return result.String()
}
