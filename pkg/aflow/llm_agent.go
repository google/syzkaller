// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"google.golang.org/genai"
)

type LLMAgent struct {
	// For logging/debugging.
	Name string
	// Name of the state variable to store the final reply of the agent.
	// These names can be used in subsequent action instructions/prompts,
	// and as final workflow outputs.
	Reply string
	// Optional additional structured outputs besides the final text reply.
	// Use LLMOutputs function to create it.
	Outputs *llmOutputs
	// Value that controls the degree of randomness in token selection.
	// Lower temperatures are good for prompts that require a less open-ended or creative response,
	// while higher temperatures can lead to more diverse or creative results.
	// Must be assigned a float32 value in the range [0, 2].
	Temperature any
	// If set, the agent will generate that many candidates and the outputs will be arrays
	// instead of scalars.
	Candidates int
	// Instructions for the agent.
	// Formatted as text/template, can use "{{.Variable}}" as placeholders for dynamic content.
	// Variables can come from the workflow inputs, or from preceding actions outputs.
	Instruction string
	// Prompt for the agent. The same format as Instruction.
	Prompt string
	// Set of tools for the agent to use.
	Tools []Tool
}

// Tool represents a custom tool an LLMAgent can invoke.
// Use NewFuncTool to create function-based tools.
type Tool interface {
	verify(*verifyContext)
	declaration() *genai.FunctionDeclaration
	execute(*Context, map[string]any) (map[string]any, error)
}

// LLMOutputs creates a special tool that can be used by LLM to provide structured outputs.
func LLMOutputs[Args any]() *llmOutputs {
	return &llmOutputs{
		tool: NewFuncTool("set-results", func(ctx *Context, state struct{}, args Args) (Args, error) {
			return args, nil
		}, "Use this tool to provide results of the analysis."),
		provideOutputs: func(ctx *verifyContext, who string, many bool) {
			if many {
				provideArrayOutputs[Args](ctx, who)
			} else {
				provideOutputs[Args](ctx, who)
			}
		},
		append: func(to, from map[string]any) {
			for name, typ := range foreachFieldOf[Args]() {
				if to[name] == nil {
					to[name] = reflect.Zero(reflect.SliceOf(typ)).Interface()
				}
				to[name] = reflect.Append(reflect.ValueOf(to[name]), reflect.ValueOf(from[name])).Interface()
			}
		},
	}
}

const llmOutputsInstruction = `

Use set-results tool to provide results of the analysis.
It must be called exactly once before the final reply.
Ignore results of this tool.
`

type llmOutputs struct {
	tool           Tool
	provideOutputs func(*verifyContext, string, bool)
	append         func(map[string]any, map[string]any)
}

func (a *LLMAgent) execute(ctx *Context) error {
	if a.Candidates <= 1 {
		reply, outputs, err := a.executeOne(ctx)
		if err != nil {
			return err
		}
		ctx.state[a.Reply] = reply
		maps.Insert(ctx.state, maps.All(outputs))
		return nil
	}
	span := &trajectory.Span{
		Type: trajectory.SpanAgentCandidates,
		Name: a.Name,
	}
	if err := ctx.startSpan(span); err != nil {
		return err
	}
	err := a.executeMany(ctx)
	return ctx.finishSpan(span, err)
}

func (a *LLMAgent) executeMany(ctx *Context) error {
	var replies []string
	allOutputs := map[string]any{}
	for candidate := 0; candidate < a.Candidates; candidate++ {
		reply, outputs, err := a.executeOne(ctx)
		if err != nil {
			return err
		}
		replies = append(replies, reply)
		if a.Outputs != nil {
			a.Outputs.append(allOutputs, outputs)
		}
	}
	ctx.state[a.Reply] = replies
	maps.Insert(ctx.state, maps.All(allOutputs))
	return nil
}

func (a *LLMAgent) executeOne(ctx *Context) (string, map[string]any, error) {
	cfg, instruction, tools := a.config(ctx)
	span := &trajectory.Span{
		Type:        trajectory.SpanAgent,
		Name:        a.Name,
		Instruction: instruction,
		Prompt:      formatTemplate(a.Prompt, ctx.state),
	}
	if err := ctx.startSpan(span); err != nil {
		return "", nil, err
	}
	reply, outputs, err := a.chat(ctx, cfg, tools, span.Prompt)
	if err == nil {
		span.Reply = reply
		span.Results = outputs
	}
	return reply, outputs, ctx.finishSpan(span, err)
}

func (a *LLMAgent) chat(ctx *Context, cfg *genai.GenerateContentConfig, tools map[string]Tool, prompt string) (
	string, map[string]any, error) {
	var outputs map[string]any
	req := []*genai.Content{genai.NewContentFromText(prompt, genai.RoleUser)}
	for {
		reqSpan := &trajectory.Span{
			Type: trajectory.SpanLLM,
			Name: a.Name,
		}
		if err := ctx.startSpan(reqSpan); err != nil {
			return "", nil, err
		}
		resp, err := a.generateContent(ctx, cfg, req)
		if err != nil {
			return "", nil, ctx.finishSpan(reqSpan, err)
		}
		reply, thoughts, calls, respErr := a.parseResponse(resp)
		reqSpan.Thoughts = thoughts
		if err := ctx.finishSpan(reqSpan, respErr); err != nil {
			return "", nil, err
		}
		if len(calls) == 0 {
			// This is the final reply.
			if a.Outputs != nil && outputs == nil {
				return "", nil, fmt.Errorf("LLM did not call tool to set outputs")
			}
			return reply, outputs, nil
		}
		// This is not the final reply, LLM asked to execute some tools.
		// Append the current reply, and tool responses to the next request.
		responses, outputs1, err := a.callTools(ctx, tools, calls)
		if err != nil {
			return "", nil, err
		}
		if outputs != nil && outputs1 != nil {
			return "", nil, fmt.Errorf("LLM called outputs tool twice")
		}
		outputs = outputs1
		req = append(req, resp.Candidates[0].Content, responses)
	}
}

func (a *LLMAgent) config(ctx *Context) (*genai.GenerateContentConfig, string, map[string]Tool) {
	instruction := formatTemplate(a.Instruction, ctx.state)
	toolList := a.Tools
	if a.Outputs != nil {
		instruction += llmOutputsInstruction
		toolList = append(toolList, a.Outputs.tool)
	}
	toolMap := make(map[string]Tool)
	var tools []*genai.Tool
	for _, tool := range toolList {
		decl := tool.declaration()
		toolMap[decl.Name] = tool
		tools = append(tools, &genai.Tool{
			FunctionDeclarations: []*genai.FunctionDeclaration{decl}})
	}
	return &genai.GenerateContentConfig{
		ResponseModalities: []string{"TEXT"},
		Temperature:        genai.Ptr(a.Temperature.(float32)),
		SystemInstruction:  genai.NewContentFromText(instruction, genai.RoleUser),
		Tools:              tools,
	}, instruction, toolMap
}

func (a *LLMAgent) callTools(ctx *Context, tools map[string]Tool, calls []*genai.FunctionCall) (
	*genai.Content, map[string]any, error) {
	responses := &genai.Content{
		Role: string(genai.RoleUser),
	}
	var outputs map[string]any
	for _, call := range calls {
		tool := tools[call.Name]
		if tool == nil {
			return nil, nil, fmt.Errorf("no tool %q", call.Name)
		}
		results, err := tool.execute(ctx, call.Args)
		if err != nil {
			return nil, nil, err
		}
		responses.Parts = append(responses.Parts, genai.NewPartFromFunctionResponse(call.Name, results))
		responses.Parts[len(responses.Parts)-1].FunctionResponse.ID = call.ID
		if a.Outputs != nil && tool == a.Outputs.tool {
			outputs = results
		}
	}
	return responses, outputs, nil
}

func (a *LLMAgent) parseResponse(resp *genai.GenerateContentResponse) (
	reply, thoughts string, calls []*genai.FunctionCall, err error) {
	if len(resp.Candidates) == 0 || resp.Candidates[0] == nil {
		err = fmt.Errorf("empty model response")
		if resp.PromptFeedback != nil {
			err = fmt.Errorf("request blocked: %v", resp.PromptFeedback.BlockReasonMessage)
		}
		return
	}
	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		err = fmt.Errorf("%v (%v)", candidate.FinishMessage, candidate.FinishReason)
		return
	}
	// We don't expect to receive these fields now.
	// Note: CitationMetadata may be present sometimes, but we don't have uses for it.
	if candidate.GroundingMetadata != nil || candidate.LogprobsResult != nil {
		err = fmt.Errorf("unexpected reply fields (%+v)", *candidate)
		return
	}
	for _, part := range candidate.Content.Parts {
		// We don't expect to receive these now.
		if part.VideoMetadata != nil || part.InlineData != nil ||
			part.FileData != nil || part.FunctionResponse != nil ||
			part.CodeExecutionResult != nil || part.ExecutableCode != nil {
			err = fmt.Errorf("unexpected reply part (%+v)", *part)
			return
		}
		if part.FunctionCall != nil {
			calls = append(calls, part.FunctionCall)
		} else if part.Thought {
			thoughts += part.Text
		} else {
			reply += part.Text
		}
	}
	return
}

func (a *LLMAgent) generateContent(ctx *Context, cfg *genai.GenerateContentConfig,
	req []*genai.Content) (*genai.GenerateContentResponse, error) {
	backoff := time.Second
	for try := 0; ; try++ {
		resp, err := ctx.generateContent(cfg, req)
		var apiErr genai.APIError
		if err != nil && try < 100 && errors.As(err, &apiErr) &&
			apiErr.Code == http.StatusServiceUnavailable {
			time.Sleep(backoff)
			backoff = min(backoff+time.Second, 10*time.Second)
			continue
		}
		return resp, err
	}
}

func (a *LLMAgent) verify(vctx *verifyContext) {
	vctx.requireNotEmpty(a.Name, "Name", a.Name)
	vctx.requireNotEmpty(a.Name, "Reply", a.Reply)
	if temp, ok := a.Temperature.(int); ok {
		a.Temperature = float32(temp)
	}
	if temp, ok := a.Temperature.(float32); !ok || temp < 0 || temp > 2 {
		vctx.errorf(a.Name, "Temperature must have a float32 value in the range [0, 2]")
	}
	if a.Candidates < 0 || a.Candidates > 100 {
		vctx.errorf(a.Name, "Candidates must be in the range [0, 100]")
	}
	// Verify dataflow. All dynamic variables must be provided by inputs,
	// or preceding actions.
	a.verifyTemplate(vctx, "Instruction", a.Instruction)
	a.verifyTemplate(vctx, "Prompt", a.Prompt)
	for _, tool := range a.Tools {
		tool.verify(vctx)
	}
	replyType := reflect.TypeFor[string]()
	if a.Candidates > 1 {
		replyType = reflect.TypeFor[[]string]()
	}
	vctx.provideOutput(a.Name, a.Reply, replyType, true)
	if a.Outputs != nil {
		a.Outputs.provideOutputs(vctx, a.Name, a.Candidates > 1)
	}
}

func (a *LLMAgent) verifyTemplate(vctx *verifyContext, what, text string) {
	vctx.requireNotEmpty(a.Name, what, text)
	vars := make(map[string]reflect.Type)
	for name, state := range vctx.state {
		vars[name] = state.typ
	}
	used, err := verifyTemplate(text, vars)
	if err != nil {
		vctx.errorf(a.Name, "%v: %v", what, err)
	}
	for name := range used {
		vctx.state[name].used = true
	}
}
