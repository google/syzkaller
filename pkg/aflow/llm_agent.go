// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/hash"
	"google.golang.org/genai"
)

type LLMAgent struct {
	// For logging/debugging.
	Name string
	// The default Gemini model name to execute this workflow.
	// Use the consts defined below.
	Model string
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
	// Must be assigned a number in the range [0, 2].
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

// Consts to use for LLMAgent.Model.
// See https://ai.google.dev/gemini-api/docs/models
const (
	BestExpensiveModel = "gemini-3-pro-preview"
	GoodBalancedModel  = "gemini-3-flash-preview"
)

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

const llmMultipleToolsInstruction = `
Prefer calling several tools at the same time to save round-trips.
`

const llmMissingReply = `You did not provide any final reply to the question. Please return something.
Or did you want to call some other tools, but did not actually do that?
`

const llmMissingOutputs = `You did not call set-results tool.
Please call set-results tool to provide results of the analysis.
Note: if you already provided you final reply, you will need to provide it again after calling set-results tool.
Or did you want to call some other tools, but did not actually do that?
`

type llmOutputs struct {
	tool           Tool
	provideOutputs func(*verifyContext, string, bool)
	append         func(map[string]any, map[string]any)
}

func (a *LLMAgent) execute(ctx *Context) error {
	if a.Candidates <= 1 {
		reply, outputs, err := a.executeOne(ctx, 0)
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
		reply, outputs, err := a.executeOne(ctx, candidate)
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

func (a *LLMAgent) executeOne(ctx *Context, candidate int) (string, map[string]any, error) {
	cfg, instruction, tools := a.config(ctx)
	span := &trajectory.Span{
		Type:        trajectory.SpanAgent,
		Name:        a.Name,
		Instruction: instruction,
		Prompt:      formatTemplate(a.Prompt, ctx.state),
		Model:       ctx.modelName(a.Model),
	}
	if err := ctx.startSpan(span); err != nil {
		return "", nil, err
	}
	reply, outputs, err := a.chat(ctx, cfg, tools, span.Prompt, candidate)
	if err == nil {
		span.Reply = reply
		span.Results = outputs
	}
	return reply, outputs, ctx.finishSpan(span, err)
}

func (a *LLMAgent) chat(ctx *Context, cfg *genai.GenerateContentConfig, tools map[string]Tool,
	prompt string, candidate int) (string, map[string]any, error) {
	var outputs map[string]any
	req := []*genai.Content{genai.NewContentFromText(prompt, genai.RoleUser)}
	for {
		reqSpan := &trajectory.Span{
			Type:  trajectory.SpanLLM,
			Name:  a.Name,
			Model: ctx.modelName(a.Model),
		}
		if err := ctx.startSpan(reqSpan); err != nil {
			return "", nil, err
		}
		resp, err := a.generateContent(ctx, cfg, req, candidate)
		if err != nil {
			return "", nil, ctx.finishSpan(reqSpan, err)
		}
		reply, calls, respErr := a.parseResponse(resp, reqSpan)
		if err := ctx.finishSpan(reqSpan, respErr); err != nil {
			return "", nil, err
		}
		req = append(req, resp.Candidates[0].Content)
		if len(calls) == 0 {
			if a.Outputs != nil && outputs == nil {
				// LLM did not call set-results.
				req = append(req, genai.NewContentFromText(llmMissingOutputs, genai.RoleUser))
				continue
			}
			if reply == "" {
				// LLM did not provide any final reply.
				req = append(req, genai.NewContentFromText(llmMissingReply, genai.RoleUser))
				continue
			}
			// This is the final reply.
			return reply, outputs, nil
		}
		// This is not the final reply, LLM asked to execute some tools.
		// Append the current reply, and tool responses to the next request.
		responses, outputs1, err := a.callTools(ctx, tools, calls)
		if err != nil {
			return "", nil, err
		}
		// Overwrite previous outputs, if LLM calls the tool more than once.
		// It shouldn't, but this seems to be the easiest way to handle it gracefully.
		outputs = outputs1
		req = append(req, responses)
	}
}

func (a *LLMAgent) config(ctx *Context) (*genai.GenerateContentConfig, string, map[string]Tool) {
	instruction := formatTemplate(a.Instruction, ctx.state)
	toolList := a.Tools
	if len(toolList) != 0 {
		instruction += llmMultipleToolsInstruction
	}
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
		Temperature:        genai.Ptr(float32(a.Temperature.(float64))),
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
		span := &trajectory.Span{
			Type: trajectory.SpanTool,
			Name: call.Name,
			Args: call.Args,
		}
		if err := ctx.startSpan(span); err != nil {
			return nil, nil, err
		}
		toolErr := BadCallError("tool %q does not exist, please correct the name", call.Name)
		tool := tools[call.Name]
		if tool != nil {
			span.Results, toolErr = tool.execute(ctx, call.Args)
		}
		if toolErr != nil {
			span.Error = toolErr.Error()
		}
		if err := ctx.finishSpan(span, nil); err != nil {
			return nil, nil, err
		}
		if toolErr != nil {
			// LLM provided wrong arguments to the tool,
			// or the tool returned error message to the LLM.
			// Return the error back to the LLM instead of failing.
			if callErr := new(badCallError); errors.As(toolErr, &callErr) {
				span.Results = map[string]any{"error": toolErr.Error()}
			} else {
				return nil, nil, fmt.Errorf("tool %v failed: error: %w\nargs: %+v",
					call.Name, toolErr, call.Args)
			}
		}
		responses.Parts = append(responses.Parts, &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				ID:       call.ID,
				Name:     call.Name,
				Response: span.Results,
			},
		})
		if toolErr == nil && a.Outputs != nil && tool == a.Outputs.tool {
			outputs = span.Results
		}
	}
	return responses, outputs, nil
}

func (a *LLMAgent) parseResponse(resp *genai.GenerateContentResponse, span *trajectory.Span) (
	reply string, calls []*genai.FunctionCall, err error) {
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
	if resp.UsageMetadata != nil {
		// We add ToolUsePromptTokenCount just in case, but Gemini does not use/set it.
		span.InputTokens = int(resp.UsageMetadata.PromptTokenCount) +
			int(resp.UsageMetadata.ToolUsePromptTokenCount)
		span.OutputTokens = int(resp.UsageMetadata.CandidatesTokenCount)
		span.OutputThoughtsTokens = int(resp.UsageMetadata.ThoughtsTokenCount)
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
			span.Thoughts += part.Text
		} else {
			reply += part.Text
		}
	}
	if strings.TrimSpace(reply) == "" {
		reply = ""
	}
	// If there is any reply along with tool calls, append it to thoughts.
	// Otherwise it won't show up in the trajectory anywhere.
	if len(calls) != 0 && reply != "" {
		span.Thoughts += "\n" + reply
	}
	return
}

func (a *LLMAgent) generateContent(ctx *Context, cfg *genai.GenerateContentConfig,
	req []*genai.Content, candidate int) (*genai.GenerateContentResponse, error) {
	backoff := time.Second
	for try := 0; ; try++ {
		resp, err := a.generateContentCached(ctx, cfg, req, candidate)
		var apiErr genai.APIError
		if err != nil && try < 100 && errors.As(err, &apiErr) &&
			apiErr.Code == http.StatusServiceUnavailable {
			time.Sleep(backoff)
			backoff = min(backoff+time.Second, 10*time.Second)
			continue
		}
		if err != nil && errors.As(err, &apiErr) && apiErr.Code == http.StatusTooManyRequests &&
			strings.Contains(apiErr.Message, "Quota exceeded for metric") {
			if match := rePleaseRetry.FindStringSubmatch(apiErr.Message); match != nil {
				sec, _ := strconv.Atoi(match[1])
				time.Sleep(time.Duration(sec+1) * time.Second)
				continue
			}
			if strings.Contains(apiErr.Message, "generate_requests_per_model_per_day") {
				return resp, &modelQuotaError{ctx.modelName(a.Model)}
			}
		}
		return resp, err
	}
}

var rePleaseRetry = regexp.MustCompile("Please retry in ([0-9]+)[.s]")

func (a *LLMAgent) generateContentCached(ctx *Context, cfg *genai.GenerateContentConfig,
	req []*genai.Content, candidate int) (*genai.GenerateContentResponse, error) {
	type Cached struct {
		Config  *genai.GenerateContentConfig
		Request []*genai.Content
		Reply   *genai.GenerateContentResponse
	}
	model := ctx.modelName(a.Model)
	desc := fmt.Sprintf("model %v, config hash %v, request hash %v, candidate %v",
		model, hash.String(cfg), hash.String(req), candidate)
	cached, err := CacheObject(ctx, "llm", desc, func() (Cached, error) {
		resp, err := ctx.generateContent(model, cfg, req)
		return Cached{
			Config:  cfg,
			Request: req,
			Reply:   resp,
		}, err
	})
	return cached.Reply, err
}

func (a *LLMAgent) verify(ctx *verifyContext) {
	ctx.requireNotEmpty(a.Name, "Name", a.Name)
	ctx.requireNotEmpty(a.Name, "Model", a.Model)
	ctx.requireNotEmpty(a.Name, "Reply", a.Reply)
	if temp, ok := a.Temperature.(int); ok {
		a.Temperature = float64(temp)
	}
	if temp, ok := a.Temperature.(float64); !ok || temp < 0 || temp > 2 {
		ctx.errorf(a.Name, "Temperature must be a number in the range [0, 2]")
	}
	if a.Candidates < 0 || a.Candidates > 100 {
		ctx.errorf(a.Name, "Candidates must be in the range [0, 100]")
	}
	// Verify dataflow. All dynamic variables must be provided by inputs,
	// or preceding actions.
	a.verifyTemplate(ctx, "Instruction", a.Instruction)
	a.verifyTemplate(ctx, "Prompt", a.Prompt)
	for _, tool := range a.Tools {
		tool.verify(ctx)
	}
	if a.Reply != llmToolReply {
		replyType := reflect.TypeFor[string]()
		if a.Candidates > 1 {
			replyType = reflect.TypeFor[[]string]()
		}
		ctx.provideOutput(a.Name, a.Reply, replyType)
		if a.Outputs != nil {
			a.Outputs.provideOutputs(ctx, a.Name, a.Candidates > 1)
		}
	}
}

func (a *LLMAgent) verifyTemplate(ctx *verifyContext, what, text string) {
	if !ctx.inputs || strings.Contains(text, llmToolPrompt) {
		return
	}
	ctx.requireNotEmpty(a.Name, what, text)
	vars := make(map[string]reflect.Type)
	for name, state := range ctx.state {
		vars[name] = state.typ
	}
	used, err := verifyTemplate(text, vars)
	if err != nil {
		ctx.errorf(a.Name, "%v: %v", what, err)
	}
	for name := range used {
		ctx.state[name].used = true
	}
}
