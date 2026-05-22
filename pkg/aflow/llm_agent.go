// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
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
	// Reply should not be empty unless Outputs are specified.
	Reply string
	// Optional additional structured outputs besides the final text reply.
	// Use LLMOutputs or ValidatedLLMOutputs functions to create it.
	Outputs *llmOutputs
	// Task type controls various LLM parameters, see TaskType consts below.
	TaskType TaskType
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

	// Number of historical message (sliding window) to keep. If zero, we don't enable the sliding
	// window summary feature (don't toss old messages).
	// Mutually exclusive with compressTokens.
	summaryWindow int

	// Token limit for historical messages. If > 0, when the total input tokens exceed this limit,
	// the agent will pause, call a cheaper model to summarize the entire history, and then drop
	// all intermediate messages, leaving only the anchor prompt and the new summary.
	// Mutually exclusive with summaryWindow.
	compressTokens int
}

type agentSession struct {
	*LLMAgent
	// Track recent tool calls for loop detection.
	toolHistory []toolCallRecord
	// req stores the active conversation history slice in this execution.
	req []*genai.Content
	// summaryMessage points to the summary message in req if the sliding window
	// summary feature is enabled. We need it to check if the message-to-be-popped
	// is a summary - if so, we need to add a new summary.
	summaryMessage *genai.Content
	// outputs stores the results returned by the final set-results tool call, if any.
	outputs map[string]any
	// answerNow is set to true when the input overflows and the agent must
	// immediately respond.
	answerNow bool
}

type toolCallRecord struct {
	Name string
	Args map[string]any
}

const (
	// Consts to use for LLMAgent.Model.
	// See https://ai.google.dev/gemini-api/docs/models
	BestExpensiveModel = "gemini-3.1-pro-preview"
	GoodBalancedModel  = "gemini-3-flash-preview"

	// Default limit for consecutive identical tool calls.
	defaultLoopDetectionLimit = 3
	maxHistorySize            = 20 // Large enough to catch alternating loops.
	// We abort execution after this many iterations to prevent infinite loops.
	defaultMaxIterations = 250
)

type TaskType int

const (
	FormalReasoningTask TaskType = iota + 1
)

// Currently we use task type to control temperature only,
// but potentially we can use it to control other parameters too
// (TopN, TopK, etc).
// Temperature controls the degree of randomness in token selection.
// Lower temperatures are good for prompts that require less open-ended
// or creative responses, while higher temperatures can lead to more
// diverse or creative results. The default temperature is 1,
// for Gemini models in value range is [0, 2].
var taskParameters = map[TaskType]float32{
	// The amount of thought put into this number is low.
	// It's basically just "we want something less random
	// for formal tasks like coding/debugging".
	FormalReasoningTask: 0.3,
}

// Tool represents a custom tool an LLMAgent can invoke.
// Use NewFuncTool to create function-based tools.
type Tool interface {
	verify(*verifyContext)
	declaration() *genai.FunctionDeclaration
	execute(*Context, map[string]any) (map[string]any, error)
}

// Tools combine all passed tools into a single slice
// avoiding aliasing issues with existing slices.
// The passed elements can be either Tool, or []Tool.
func Tools(tools ...any) []Tool {
	var res []Tool
	for _, t := range tools {
		switch tool := t.(type) {
		case Tool:
			res = append(res, tool)
		case []Tool:
			res = append(res, tool...)
		default:
			panic(fmt.Sprintf("unsupported type %T", t))
		}
	}
	return res
}

// LLMOutputs creates a special tool that can be used by LLM to provide structured outputs.
func LLMOutputs[Args any]() *llmOutputs {
	return ValidatedLLMOutputs[Args, struct{}](nil)
}

// ValidatedLLMOutputs is like LLMOutputs but allows to validate the outputs before accepting them.
// The validate function may return modified Args, which will be used as the final result.
// If the validate function returns an error, it will be returned to the LLM agent,
// so that it can retry the call. Use BadCallError if LLM must retry.
func ValidatedLLMOutputs[Args, State any](validate func(*Context, State, Args) (Args, error)) *llmOutputs {
	return &llmOutputs{
		tool: NewFuncTool(llmSetResultsTool, func(ctx *Context, state State, args Args) (Args, error) {
			if validate != nil {
				var err error
				if args, err = validate(ctx, state, args); err != nil {
					return args, err
				}
			}
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

const llmSetResultsTool = "set-results"

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

const llmAnswerNow = `
Provide a best-effort answer to the original question with all of the information
you have so far without calling any more tools!
`

const slidingWindowInstruction = `
You MUST attach a summary of your most up-to-date findings/knowledge in your reply, which summarizes
all the historical context, because I will remove old chats if they fall out of the context sliding window
(for example, I will remove the oldest 3 chats if the sliding window is 10 but there have been 13 LLM chat
messages). In your summary, KEEP/INCLUDE ALL useful code. Because I will drop old messages, the code read
by tools will also be tossed.
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
	for candidate := range a.Candidates {
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
	cfg, instruction, prompt, tools := a.config(ctx)

	span := &trajectory.Span{
		Type:        trajectory.SpanAgent,
		Name:        a.Name,
		Instruction: instruction,
		Prompt:      prompt,
		Model:       ctx.modelName(a.Model),
	}
	if err := ctx.startSpan(span); err != nil {
		return "", nil, err
	}
	s := &agentSession{LLMAgent: a}
	reply, outputs, err := s.chat(ctx, cfg, tools, instruction, span.Prompt, candidate)
	if err == nil {
		span.Reply = reply
		span.Results = outputs
	}
	return reply, outputs, ctx.finishSpan(span, err)
}

func (a *agentSession) handleOverflowError(cfg *genai.GenerateContentConfig) bool {
	if a.Reply == llmToolReply && len(a.req) >= 3 && !a.answerNow {
		cfg.ToolConfig = &genai.ToolConfig{
			FunctionCallingConfig: &genai.FunctionCallingConfig{
				Mode: genai.FunctionCallingConfigModeNone,
			},
		}
		a.req[len(a.req)-1] = genai.NewContentFromText(llmAnswerNow, genai.RoleUser)
		return true
	}
	return false
}

func (a *agentSession) chat(ctx *Context, cfg *genai.GenerateContentConfig, tools map[string]Tool,
	instruction, prompt string, candidate int) (string, map[string]any, error) {
	a.req = []*genai.Content{genai.NewContentFromText(prompt, genai.RoleUser)}
	var lastInputTokens int
	var anchorTokens int
	for range defaultMaxIterations {
		var err error
		tokensToCompress := max(0, lastInputTokens-anchorTokens)
		compressed, err := a.maybeCompressContext(ctx, instruction, tokensToCompress)
		if err != nil {
			return "", nil, err
		}
		if compressed {
			// Reset tokens to 0 so that if the main API call fails (e.g., token overflow)
			// and the loop retries via `continue`, it doesn't immediately try to
			// compress the already-compressed context again. The real token count
			// will be fetched from the next successful API response.
			lastInputTokens = 0
		}

		span := &trajectory.Span{
			Type:  trajectory.SpanLLM,
			Name:  a.Name,
			Model: ctx.modelName(a.Model),
		}
		if err := ctx.startSpan(span); err != nil {
			return "", nil, err
		}
		addNewSummary := a.slide()
		resp, respErr := a.generateContent(ctx, cfg, a.req, candidate)

		if resp != nil && resp.UsageMetadata != nil {
			lastInputTokens = int(resp.UsageMetadata.PromptTokenCount)
			if anchorTokens == 0 {
				anchorTokens = lastInputTokens
			}
		}

		if respErr != nil {
			span.Error = respErr.Error()
			if err := ctx.finishSpan(span, nil); err != nil {
				return "", nil, err
			}
			// Input overflows maximum number of tokens.
			// If this is an LLMTool, we remove the last tool reply,
			// and replace it with an order to answer right now.
			if isInputTokenOverflowError(respErr) {
				if a.handleOverflowError(cfg) {
					a.answerNow = true
					continue
				}
			}
			return "", nil, respErr
		}
		reply, calls, respErr := a.parseResponse(resp, span)
		if err := ctx.finishSpan(span, respErr); err != nil {
			return "", nil, err
		}
		// If the LLM did not provide any reply and does not want to call any
		// tools, we got an empty response. Populate the `Part`s with `Text`
		// before appending to the history to avoid `INVALID_ARGUMENT` errors.
		if reply == "" && len(calls) == 0 {
			resp.Candidates[0].Content.Parts = []*genai.Part{{Text: "empty"}}
		}
		a.req = append(a.req, resp.Candidates[0].Content)

		// We told LLM to add a new summary. Let's re-direct the pointer to it.
		if addNewSummary {
			a.summaryMessage = a.req[len(a.req)-1]
		}
		if len(calls) == 0 {
			if missing := a.checkFinalReply(reply); missing != nil {
				a.req = append(a.req, missing)
				continue
			}
			// This is the final reply.
			return reply, a.outputs, nil
		}
		// This is not the final reply, LLM asked to execute some tools.
		// Append the current reply, and tool responses to the next request.
		err = a.callTools(ctx, tools, calls)
		if err != nil {
			return "", nil, err
		}
		if a.outputs != nil {
			if a.Reply == "" {
				return "", a.outputs, nil
			}
		}
	}
	return "", nil, fmt.Errorf("agent reached max iterations limit (%v)",
		defaultMaxIterations)
}

func (a *agentSession) checkFinalReply(reply string) *genai.Content {
	if a.Outputs != nil && a.outputs == nil {
		// LLM did not call set-results.
		return genai.NewContentFromText(llmMissingOutputs, genai.RoleUser)
	}
	if reply == "" {
		// LLM did not provide any final reply.
		return genai.NewContentFromText(llmMissingReply, genai.RoleUser)
	}
	return nil
}

const tokenCompressionInstruction = `
You are an expert technical assistant acting as a memory compressor.
Review the following execution history of an AI agent.

The first message begins with the original system instructions enclosed in
<system_instructions> tags, and then continues with the initial prompt.
These are provided for your information and will be preserved in the history
anyway, so DO NOT duplicate their contents in your summary.

Write a comprehensive and substantial summary of the current state of the workspace
and the investigation based on the SUBSEQUENT messages. Do NOT write a very short summary.
Include:
1. A detailed list of what approaches have been tried so far and their results (including dead-ends).
2. The current hypotheses, theories, or active lines of investigation.
3. Any specific file paths, code snippets, or configuration values that are critical to remember.
4. Watch out for potential reasoning loops or repetitive tool calls and explicitly note them.

You MUST provide the summary in your final response text. Do not use tools.
`

// We use a very low temperature for the compressor to ensure it acts as a strict,
// deterministic summarizer of facts without hallucinating or adding creative leaps.
const tokenCompressionTemperature = 0.1

func (a *agentSession) compressContext(ctx *Context, instruction string) (*genai.Content, error) {
	// Lightweight config targeting the Flash model.
	cfg := &genai.GenerateContentConfig{
		Temperature:       genai.Ptr[float32](tokenCompressionTemperature),
		SystemInstruction: genai.NewContentFromText(tokenCompressionInstruction, genai.RoleUser),
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingLevel:   genai.ThinkingLevelHigh,
		},
	}

	span := &trajectory.Span{
		Type:  trajectory.SpanLLM,
		Name:  a.Name + "-compressor",
		Model: ctx.modelName(GoodBalancedModel),
	}
	if err := ctx.startSpan(span); err != nil {
		return nil, err
	}

	compressReq := slices.Clone(a.req)
	if instruction != "" && len(compressReq) > 0 {
		compressReq[0] = osutil.JSONDeepCopy(compressReq[0])
		if len(compressReq[0].Parts) > 0 {
			compressReq[0].Parts[0] = &genai.Part{
				Text: "<system_instructions>\n" + instruction + "\n</system_instructions>\n\n" + compressReq[0].Parts[0].Text,
			}
		}
	}

	// We append a final prompt to ensure the model knows it must summarize now,
	// rather than trying to continue the original conversation.
	compressReq = append(compressReq, genai.NewContentFromText(
		"Task: Provide the comprehensive summary of the above execution history now.\n"+
			"Important: You must output the actual summary text in your final response. "+
			"Do NOT use any tools.",
		genai.RoleUser,
	))

	resp, err := a.generateContent(ctx, cfg, compressReq, 0)
	if err != nil {
		return nil, ctx.finishSpan(span, err)
	}

	reply, _, respErr := a.parseResponse(resp, span)

	// We want the model to "think" for better reasoning during compression,
	// but we don't want to clutter the trajectory UI with those thoughts.
	span.Thoughts = ""

	if respErr != nil {
		return nil, ctx.finishSpan(span, respErr)
	}

	reply = strings.TrimSpace(reply)
	if reply == "" {
		reply = "(The summarizer agent returned an empty summary)"
	}

	span.Reply = reply

	newSummary := genai.NewContentFromText(
		"Here is the summary of the previous execution history:\n\n"+reply,
		genai.RoleUser,
	)

	return newSummary, ctx.finishSpan(span, nil)
}

func (a *agentSession) maybeCompressContext(ctx *Context, instruction string, tokensToCompress int) (bool, error) {
	if a.compressTokens == 0 || tokensToCompress <= a.compressTokens {
		// Return existing state unchanged.
		return false, nil
	}

	newSummary, err := a.compressContext(ctx, instruction)
	if err != nil {
		return false, fmt.Errorf("context compression failed: %w", err)
	}

	// Truncate history to Anchor + Summary.
	a.req = []*genai.Content{a.req[0], newSummary}
	// If compression happened, reset the existing summaryMessage to nil.
	a.summaryMessage = nil
	return true, nil
}

func (a *agentSession) slide() bool {
	// Sliding window optimization: keep index 0 (anchor) and the last summaryWindow-1 messages
	// (recent history), then discard the old ones with stale context and to free up tokens.
	// We need to add a new summary if we don't have one yet, or existing summary is going to be popped.
	if a.summaryWindow <= 0 || len(a.req) <= a.summaryWindow {
		return false
	}
	// If we haven't created a summary, surely need to create one.
	addNewSummary := a.summaryMessage == nil
	// popEnd is the last index of elements to be popped
	popEnd := len(a.req) - a.summaryWindow
	// If we already have a summary, we iterate through the elements being popped
	// (index 1 to popEnd), and see if the summary would be popped (hence needing
	// a new summary).
	for i := 1; i <= popEnd; i++ {
		if a.req[i] == a.summaryMessage {
			// The existing summary message is among the elements being popped.
			addNewSummary = true
			break
		}
	}
	// Append the very prompt, asking LLM to add summary.
	// TODO: what if it is ready to provide an answer right now,
	// and don't want to call any tools anymore, but instead we
	// ask it to summarize? We may get the summary as the final reply...
	// Or, what if it summarizes w/o calling any tools?
	if addNewSummary {
		a.req[len(a.req)-1].Parts = append(a.req[len(a.req)-1].Parts, &genai.Part{
			Text: slidingWindowInstruction,
		})
	}
	// The actual popping.
	if addNewSummary && (a.summaryMessage != nil) {
		// Before we actually pop the old summary, save it so the new summary can
		// incorporate enough old information.
		a.req = append([]*genai.Content{a.req[0], a.summaryMessage}, a.req[popEnd+1:]...)
	} else {
		a.req = append([]*genai.Content{a.req[0]}, a.req[popEnd+1:]...)
	}
	return addNewSummary
}

func (a *LLMAgent) config(ctx *Context) (*genai.GenerateContentConfig, string, string, map[string]Tool) {
	toolList := a.Tools
	if a.Outputs != nil {
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
	state := maps.Clone(ctx.state)
	for name := range toolMap {
		state[toolTemplateName(name)] = name
	}
	instruction := formatTemplate(a.Instruction, state)
	if len(a.Tools) != 0 {
		instruction += llmMultipleToolsInstruction
	}
	if a.Outputs != nil {
		instruction += llmOutputsInstruction
	}
	prompt := formatTemplate(a.Prompt, state)
	return &genai.GenerateContentConfig{
		ResponseModalities: []string{"TEXT"},
		Temperature:        genai.Ptr(taskParameters[a.TaskType]),
		SystemInstruction:  genai.NewContentFromText(instruction, genai.RoleUser),
		Tools:              tools,
		ThinkingConfig: &genai.ThinkingConfig{
			// We capture them in the trajectory for analysis.
			IncludeThoughts: true,
			// Enable "dynamic thinking" ("the model will adjust the budget based on the complexity of the request").
			// See https://ai.google.dev/gemini-api/docs/thinking#set-budget
			// However, thoughts output also consumes total output token budget.
			// We may consider adjusting ThinkingLevel parameter.
			//
			// Gemini says ThinkingLevel and ThinkingBudget specify the same,
			// but in different ways. ThinkingBudget is precise token count.
			// ThinkingLevel is an abstract level that maps to some unspecified
			// number of tokens. Settings are mutually exclusive,
			// we use ThinkingLevel.
			ThinkingLevel: genai.ThinkingLevelHigh,
		},
	}, instruction, prompt, toolMap
}

func (a *agentSession) callTools(ctx *Context, tools map[string]Tool, calls []*genai.FunctionCall) error {
	responses := &genai.Content{
		Role: string(genai.RoleUser),
	}
	for _, call := range calls {
		span := &trajectory.Span{
			Type: trajectory.SpanTool,
			Name: call.Name,
			Args: call.Args,
		}
		if err := ctx.startSpan(span); err != nil {
			return err
		}
		toolErr := BadCallError("tool %q does not exist, please correct the name", call.Name)
		tool := tools[call.Name]
		if tool != nil {
			if err := a.checkDuplicateCall(call); err != nil {
				toolErr = err
			} else {
				a.recordToolCall(call.Name, call.Args)
				span.Results, toolErr = tool.execute(ctx, call.Args)
			}
		}
		if toolErr != nil {
			span.Error = toolErr.Error()
		}
		if err := ctx.finishSpan(span, nil); err != nil {
			return err
		}
		if toolErr != nil {
			// LLM provided wrong arguments to the tool,
			// or the tool returned error message to the LLM.
			// Return the error back to the LLM instead of failing.
			if callErr := new(badCallError); errors.As(toolErr, &callErr) {
				span.Results = map[string]any{"error": toolErr.Error()}
			} else {
				return fmt.Errorf("tool %v failed: error: %w\nargs: %+v",
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
			a.outputs = span.Results
		}
	}
	a.req = append(a.req, responses)
	return nil
}

func (a *LLMAgent) parseResponse(resp *genai.GenerateContentResponse, span *trajectory.Span) (
	reply string, calls []*genai.FunctionCall, err error) {
	candidate := resp.Candidates[0]
	if resp.UsageMetadata != nil {
		// We add ToolUsePromptTokenCount just in case, but Gemini does not use/set it.
		span.InputTokens = int(resp.UsageMetadata.PromptTokenCount) +
			int(resp.UsageMetadata.ToolUsePromptTokenCount)
		span.OutputTokens = int(resp.UsageMetadata.CandidatesTokenCount)
		span.OutputThoughtsTokens = int(resp.UsageMetadata.ThoughtsTokenCount)
	}
	for _, part := range candidate.Content.Parts {
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
	// Copy the config in case we modify it below.
	cfg = osutil.JSONDeepCopy(cfg)
	for try := 0; ; try++ {
		resp, err := a.generateContentCached(ctx, cfg, req, candidate, try)
		if retryErr := new(retryError); errors.As(err, &retryErr) {
			time.Sleep(retryErr.delay)
			continue
		}
		if isOutputTokenOverflowError(err) &&
			cfg.ThinkingConfig.ThinkingLevel != genai.ThinkingLevelMinimal {
			// Reduce amount of thinking and try again (thinking tokens are counted against output).
			// For non-thinking models this is effectively just a retry,
			// but that's fine, there is some chance that retry will succeed due to randomness,
			// or it will just fail after few retries.
			switch cfg.ThinkingConfig.ThinkingLevel {
			case genai.ThinkingLevelHigh:
				cfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelMedium
			case genai.ThinkingLevelMedium:
				cfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelLow
			case genai.ThinkingLevelLow:
				cfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelMinimal
			default:
				return nil, fmt.Errorf("unexpected thinking level %v", cfg.ThinkingConfig.ThinkingLevel)
			}
			continue
		}
		return resp, err
	}
}

func (a *LLMAgent) generateContentCached(ctx *Context, cfg *genai.GenerateContentConfig,
	req []*genai.Content, candidate, try int) (*genai.GenerateContentResponse, error) {
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
		err = parseLLMError(resp, err, model, try)
		return Cached{
			Config:  cfg,
			Request: req,
			Reply:   resp,
		}, err
	})
	return cached.Reply, err
}

func parseLLMError(resp *genai.GenerateContentResponse, err error, model string, try int) error {
	err = parseLLMErrorImpl(resp, err, model, try)
	if retryErr := new(retryError); errors.As(err, &retryErr) && try >= maxLLMRetryIters {
		// We can't retry infinity, so revert back to the original error
		// when we reach maxLLMRetryIters.
		return retryErr.err
	}
	return err
}

func parseLLMErrorImpl(resp *genai.GenerateContentResponse, err error, model string, try int) error {
	if err == nil {
		return parseLLMResp(resp)
	}
	var apiErr genai.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if apiErr.Code == http.StatusServiceUnavailable ||
		apiErr.Code == http.StatusBadGateway ||
		apiErr.Code == http.StatusGatewayTimeout ||
		// 499 has server-dependent meaning, but for genapi we observed these
		// when a request was cancelled on some internal error.
		apiErr.Code == 499 {
		return &retryError{llmBackoffDuration(try), err}
	}
	if apiErr.Code == http.StatusTooManyRequests &&
		strings.Contains(apiErr.Message, "Quota exceeded for metric") {
		if match := rePleaseRetry.FindStringSubmatch(apiErr.Message); match != nil {
			sec, _ := strconv.Atoi(match[1])
			return &retryError{time.Duration(sec+1) * time.Second, err}
		}
		if strings.Contains(apiErr.Message, "generate_requests_per_model_per_day") {
			return &modelQuotaError{model}
		}
	}
	if apiErr.Code == http.StatusTooManyRequests &&
		strings.Contains(apiErr.Message, "You exceeded your current quota") {
		// Unclear what this is, the error does not contain details
		// (see the test for exact error message). But presumably this is some per-minute quota.
		return &retryError{time.Minute, err}
	}
	if apiErr.Code == http.StatusTooManyRequests &&
		(strings.Contains(apiErr.Message, "Resource exhausted. Please try again later.") ||
			strings.Contains(apiErr.Message, "Resource has been exhausted")) {
		// Vertex AI specific rate limit error (e.g. RPM/TPM exhausted).
		return &retryError{time.Minute, err}
	}
	if apiErr.Code == http.StatusBadRequest &&
		strings.Contains(apiErr.Message, "The input token count exceeds the maximum") {
		return &inputTokenOverflowError{err}
	}
	if apiErr.Code == http.StatusInternalServerError {
		// Let's assume ISE is just something temporal on the server side.
		return &retryError{time.Second, err}
	}
	return err
}

func llmBackoffDuration(try int) time.Duration {
	backoff := time.Second
	// Use loop instead of math.Pow to properly handle overflow.
	for range try {
		backoff *= 2
		if backoff >= maxLLMBackoff {
			return maxLLMBackoff
		}
	}
	return backoff
}

func parseLLMResp(resp *genai.GenerateContentResponse) error {
	if len(resp.Candidates) == 0 || resp.Candidates[0] == nil {
		if resp.PromptFeedback != nil {
			return fmt.Errorf("request blocked: %v", resp.PromptFeedback.BlockReasonMessage)
		}
		return fmt.Errorf("empty model response")
	}
	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		if candidate.FinishReason == genai.FinishReasonMalformedFunctionCall {
			// Let's consider this as a temp error, and that the next time it won't
			// generate the same buggy output. In either case we have maxLLMRetryIters.
			return &retryError{0, errors.New(string(candidate.FinishReason))}
		}
		if candidate.FinishReason == genai.FinishReasonMaxTokens {
			return &outputTokenOverflowError{errors.New(string(candidate.FinishReason))}
		}
		return fmt.Errorf("%v (%v)", candidate.FinishMessage, candidate.FinishReason)
	}
	// We don't expect to receive these fields now.
	// Note: CitationMetadata may be present sometimes, but we don't have uses for it.
	if candidate.GroundingMetadata != nil || candidate.LogprobsResult != nil {
		return fmt.Errorf("unexpected reply fields (%+v)", *candidate)
	}
	for _, part := range candidate.Content.Parts {
		// We don't expect to receive these now.
		if part.VideoMetadata != nil || part.InlineData != nil ||
			part.FileData != nil || part.FunctionResponse != nil ||
			part.CodeExecutionResult != nil || part.ExecutableCode != nil {
			return fmt.Errorf("unexpected reply part (%+v)", *part)
		}
	}
	return nil
}

const (
	maxLLMRetryIters = 100
	maxLLMBackoff    = 5 * time.Minute
)

var rePleaseRetry = regexp.MustCompile("Please retry in ([0-9]+)[.s]")

type retryError struct {
	delay time.Duration
	err   error
}

func (err *retryError) Error() string {
	return fmt.Sprintf("%s (should be retried after %v)", err.err, err.delay)
}

func (err *retryError) Unwrap() error {
	return err.err
}

func (a *LLMAgent) verify(ctx *verifyContext) {
	if a.summaryWindow != 0 && a.compressTokens != 0 {
		ctx.errorf(a.Name, "summaryWindow and compressTokens are mutually exclusive")
	}
	if a.compressTokens == 0 && a.summaryWindow == 0 {
		// Empirically good value we use by default.
		a.compressTokens = 200_000
	}
	ctx.requireNotEmpty(a.Name, "Name", a.Name)
	ctx.requireNotEmpty(a.Name, "Model", a.Model)
	if a.Outputs == nil {
		ctx.requireNotEmpty(a.Name, "Reply", a.Reply)
	}
	if _, ok := taskParameters[a.TaskType]; !ok {
		ctx.errorf(a.Name, "bad or missing TaskType (%v)", a.TaskType)
	}
	if a.Candidates < 0 || a.Candidates > 100 {
		ctx.errorf(a.Name, "Candidates must be in the range [0, 100]")
	}
	// Verify dataflow. All dynamic variables must be provided by inputs,
	// or preceding actions.
	a.verifyTemplate(ctx, "Instruction", a.Instruction)
	a.verifyTemplate(ctx, "Prompt", a.Prompt)
	for _, tool := range a.Tools {
		name := tool.declaration().Name
		if !toolNameRe.MatchString(name) {
			ctx.errorf(a.Name, "bad tool name %q, expect %s", name, toolNameRe)
		}
		tool.verify(ctx)
	}
	if a.Reply != llmToolReply {
		replyType := reflect.TypeFor[string]()
		if a.Candidates > 1 {
			replyType = reflect.TypeFor[[]string]()
		}
		if a.Reply != "" {
			ctx.provideOutput(a.Name, a.Reply, replyType)
		}
		if a.Outputs != nil {
			a.Outputs.tool.verify(ctx)
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
	for _, tool := range a.Tools {
		name := tool.declaration().Name
		templName := toolTemplateName(name)
		if _, ok := vars[templName]; ok {
			ctx.errorf(a.Name, "tool %q is duplicated", name)
			return
		}
		vars[templName] = reflect.TypeFor[string]()
	}
	used, err := verifyTemplate(text, vars)
	if err != nil {
		ctx.errorf(a.Name, "%v: %v", what, err)
	}
	for name := range used {
		if ctx.state[name] != nil {
			ctx.state[name].used = true
		}
	}
}

func (a *agentSession) recordToolCall(name string, args map[string]any) {
	a.toolHistory = append(a.toolHistory, toolCallRecord{Name: name, Args: args})
	if len(a.toolHistory) > maxHistorySize {
		a.toolHistory = a.toolHistory[1:] // Keep it a rolling window.
	}
}

func (a *agentSession) checkDuplicateCall(call *genai.FunctionCall) error {
	limit := defaultLoopDetectionLimit
	if len(a.toolHistory) < limit {
		return nil
	}

	repeats := 0
	for _, record := range a.toolHistory {
		if record.Name == call.Name && reflect.DeepEqual(record.Args, call.Args) {
			repeats++
		}
	}

	if repeats >= limit {
		return BadCallError("You are repeating the same tool call with the exact same arguments. " +
			"Please synthesize the information you already have instead of repeating queries.")
	}

	return nil
}

var toolNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]+[a-z0-9]$`)

func toolTemplateName(name string) string {
	buf := new(bytes.Buffer)
	buf.WriteString("tool")
	cap := true
	for _, c := range name {
		if c == '-' {
			cap = true
			continue
		}
		if cap {
			buf.WriteRune(unicode.ToUpper(c))
		} else {
			buf.WriteRune(c)
		}
		cap = false
	}
	return buf.String()
}
