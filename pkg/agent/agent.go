// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package agent

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	adk "google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/genai"
)

type Agent interface {
	create(*createContext) (adk.Agent, error)
	verify(*verifyContext)
}

type LLMAgent struct {
	// For logging/debugging only.
	Name        string
	OutputKey   string
	Instruction string
	Prompt      string
	Tools       []Tool
}

type SequentialAgent struct {
	// For logging/debugging only.
	Name   string
	Agents []Agent
}

type createContext struct {
	llm           model.LLM
	contentConfig *genai.GenerateContentConfig
}

type verifyContext struct {
	state map[string]bool
	err   error
}

func (a *LLMAgent) create(cctx *createContext) (adk.Agent, error) {
	var tools []tool.Tool
	for _, t := range a.Tools {
		tool, err := t.create(cctx)
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return llmagent.New(llmagent.Config{
		Name:                     a.Name,
		GenerateContentConfig:    cctx.contentConfig,
		Model:                    cctx.llm,
		Instruction:              a.Instruction,
		IncludeContents:          llmagent.IncludeContentsNone,
		BeforeModelCallbacks:     []llmagent.BeforeModelCallback{a.beforeModel},
		Tools:                    tools,
		OutputKey:                a.OutputKey,
		DisallowTransferToParent: true,
		DisallowTransferToPeers:  true,
	})
}

func (a *LLMAgent) beforeModel(ctx adk.CallbackContext, req *model.LLMRequest) (*model.LLMResponse, error) {
	if len(req.Contents) == 1 && len(req.Contents[0].Parts) == 2 && req.Contents[0].Parts[0].Text == "For context:" {
		req.Contents = nil
	}
	if len(req.Contents) == 0 {
		prompt := formatPrompt(a.Prompt, ctx.State())
		req.Contents = append(req.Contents, genai.NewContentFromText(prompt, genai.RoleUser))
	}

	fmt.Printf("REQUEST FOR AGENT %v\n", a.Name)
	if req.Config.SystemInstruction != nil {
		for i, part := range req.Config.SystemInstruction.Parts {
			fmt.Printf("REQ: INSTRUCTION %v: %v\n", i, part.Text)
		}
	}
	for i, content := range req.Contents {
		for j, part := range content.Parts {
			fmt.Printf("REQ: CONTENTS %v/%v: %v\n", i, j, part.Text)
		}
	}
	return nil, nil
}

var promptPlaceholderRe = regexp.MustCompile(`{+([^{}]*)}+`)

func (a *LLMAgent) verify(vctx *verifyContext) {
	for _, name := range promptPlaceholderRe.FindAllStringSubmatch(a.Prompt, -1) {
		if !vctx.state[name[1]] && vctx.err == nil {
			vctx.err = fmt.Errorf("agent %v does not have input %v, available inputs: %v",
				a.Name, name[1], slices.Collect(maps.Keys(vctx.state)))
		}
	}
	if a.OutputKey != "" {
		if vctx.state[a.OutputKey] && vctx.err == nil {
			vctx.err = fmt.Errorf("agent %v output %v is already set",
				a.Name, a.OutputKey)
		}
		vctx.state[a.OutputKey] = true
	}
}

func formatPrompt(template string, state session.State) string {
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

func (a *SequentialAgent) create(cctx *createContext) (adk.Agent, error) {
	var agents []adk.Agent
	for _, sub := range a.Agents {
		subAgent, err := sub.create(cctx)
		if err != nil {
			return nil, err
		}
		agents = append(agents, subAgent)
	}
	return sequentialagent.New(sequentialagent.Config{
		AgentConfig: adk.Config{
			Name:      a.Name,
			SubAgents: agents,
		},
	})
}

func (a *SequentialAgent) verify(vctx *verifyContext) {
	for _, a := range a.Agents {
		a.verify(vctx)
	}
}
