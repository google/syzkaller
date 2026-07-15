// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/hash"
)

type LLMAgent struct {
	// For logging/debugging.
	Name string
	// The default Gemini model name to execute this workflow.
	// Use the consts defined below.
	Model backend.ModelCategory
	// Name of the state variable to store the final reply of the agent.
	// These names can be used in subsequent action instructions/prompts,
	// and as final workflow outputs.
	// Reply should not be empty unless Outputs are specified.
	Reply string
	// Similar to Reply, but allows to validate/fixup LLM replies using the provided callback function.
	// Use LLMReply function to create it.
	ValidatedReply *llmReply
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

	// Token limit for historical messages. If > 0, when the total input tokens exceed this limit,
	// the agent will pause, call a cheaper model to summarize the entire history, and then drop
	// all intermediate messages, leaving only the anchor prompt and the new summary.
	compressTokens int
}

type agentSession struct {
	*LLMAgent
	// Track recent tool calls for loop detection.
	toolHistory []toolCallRecord
	// req stores the active conversation history slice in this execution.
	req []llmMessage
	// outputs stores the results returned by the final set-results tool call, if any.
	outputs map[string]any
	// answerNow is set to true when the input overflows and the agent must
	// immediately respond.
	answerNow bool
}

type llmMessage struct {
	content    *backend.Message
	tokenCount int // tokens consumed by this message
}

type toolCallRecord struct {
	Name string
	Args map[string]any
}

const (
	// Consts to use for LLMAgent.Model.
	// These are aliases for the backend constants to avoid requiring users
	// of the aflow package to import the backend package just to specify the model.
	BestExpensiveModel = backend.BestExpensiveModel
	GoodBalancedModel  = backend.GoodBalancedModel

	// Default limit for consecutive identical tool calls.
	defaultLoopDetectionLimit = 3
	hardLoopDetectionLimit    = 6
	maxHistorySize            = 20 // Large enough to catch alternating loops.
	// We abort execution after this many iterations to prevent infinite loops.
	maxLLMIterations = 250
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
	declaration() *backend.FunctionDeclaration
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

func LLMReply[State any](name string, validate func(*Context, State, string) (string, error)) *llmReply {
	return &llmReply{
		name: name,
		verify: func(ctx *verifyContext) {
			ctx.requireNotEmpty("LLMReply", "Name", name)
			requireInputs[State](ctx, name)
		},
		execute: func(ctx *Context, reply string) (string, error) {
			state, err := convertFromMap[State](ctx.state, false, false)
			if err != nil {
				return "", err
			}
			return validate(ctx, state, reply)
		},
	}
}

type llmReply struct {
	name    string
	verify  func(*verifyContext)
	execute func(*Context, string) (string, error)
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

const llmBadReply = `Your last reply did not pass verification with the following error.
Correct your reply accordingly.

Error:
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

const llmDuplicateCallWarning = `You are repeating the same tool call with the exact same arguments.
You already have the result of this exact tool call in your conversation history.
Do NOT request it again. You MUST synthesize the information you already have,
try a completely different tool, or proceed to the next step.`

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
		Model:       string(a.Model),
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

func (a *agentSession) tryAnswerNow(cfg *backend.GenerateConfig, overflow bool) bool {
	if a.Reply != llmToolReply || len(a.req) < 3 || a.answerNow {
		return false
	}
	a.answerNow = true
	// We clear the tools to force the model to provide a text answer instead of calling a tool.
	cfg.Tools = nil

	request := llmMessage{content: &backend.Message{
		Role:  backend.RoleUser,
		Parts: []backend.Part{{Text: llmAnswerNow}},
	}}
	if overflow {
		a.req[len(a.req)-1] = request
	} else {
		a.req = append(a.req, request)
	}
	return true
}

func (a *agentSession) chat(ctx *Context, cfg *backend.GenerateConfig, tools map[string]Tool,
	instruction, prompt string, candidate int) (string, map[string]any, error) {
	a.req = []llmMessage{{content: &backend.Message{
		Role:  backend.RoleUser,
		Parts: []backend.Part{{Text: prompt}},
	}}}
	var anchorTokens int
	for iter := 0; iter < maxLLMIterations || a.tryAnswerNow(cfg, false); iter++ {
		var currentInputTokens int
		for _, msg := range a.req {
			currentInputTokens += msg.tokenCount
		}
		tokensToCompress := max(0, currentInputTokens-anchorTokens)
		_, err := a.maybeCompressContext(ctx, instruction, tokensToCompress)
		if err != nil {
			return "", nil, err
		}
		// Context has been compressed. The preserved messages have valid
		// token counts and the total is small, so we don't need to reset tokens here.

		span := &trajectory.Span{
			Type:  trajectory.SpanLLM,
			Name:  a.Name,
			Model: string(a.Model),
		}
		if err := ctx.startSpan(span); err != nil {
			return "", nil, err
		}
		var rawReq []*backend.Message
		for _, msg := range a.req {
			rawReq = append(rawReq, msg.content)
		}
		resp, respErr := a.generateContent(ctx, cfg, rawReq, candidate, a.Model, span)

		if respErr != nil {
			span.Error = respErr.Error()
			if err := ctx.finishSpan(span, nil); err != nil {
				return "", nil, err
			}
			// Input overflows maximum number of tokens.
			// If this is an LLMTool, we remove the last tool reply,
			// and replace it with an order to answer right now.
			if isInputTokenOverflowError(respErr) {
				if a.tryAnswerNow(cfg, true) {
					// This avoids a corner case when we overflowed the context
					// on the very last iteration before maxLLMIterations.
					iter--
					continue
				}
			}
			return "", nil, respErr
		}
		reply, calls, respErr := a.parseResponse(resp, span)
		if err := ctx.finishSpan(span, respErr); err != nil {
			return "", nil, err
		}

		if span.InputTokens > 0 {
			var assignedTokens int
			for _, msg := range a.req {
				assignedTokens += msg.tokenCount
			}
			newTokens := span.InputTokens - assignedTokens
			if newTokens > 0 {
				a.req[len(a.req)-1].tokenCount += newTokens
			}
			if anchorTokens == 0 {
				anchorTokens = span.InputTokens
			}
		}

		// If the LLM did not provide any reply and does not want to call any
		// tools, we got an empty response. Populate the `Part`s with `Text`
		// before appending to the history to avoid `INVALID_ARGUMENT` errors.
		if reply == "" && len(calls) == 0 {
			resp.Parts = []backend.Part{{Text: "empty"}}
		}
		a.req = append(a.req, llmMessage{
			content:    &backend.Message{Role: backend.RoleModel, Parts: resp.Parts},
			tokenCount: span.OutputTokens,
		})

		if len(calls) == 0 {
			reply, wrong, err := a.checkFinalReply(ctx, reply)
			if err != nil {
				return "", nil, err
			}
			if wrong != "" {
				a.req = append(a.req, llmMessage{content: &backend.Message{
					Role:  backend.RoleUser,
					Parts: []backend.Part{{Text: wrong}},
				}})
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
		maxLLMIterations)
}

func (a *agentSession) checkFinalReply(ctx *Context, reply string) (string, string, error) {
	if a.Outputs != nil && a.outputs == nil {
		// LLM did not call set-results.
		return "", llmMissingOutputs, nil
	}
	if reply == "" {
		// LLM did not provide any final reply.
		return "", llmMissingReply, nil
	}
	if a.ValidatedReply != nil {
		var err error
		reply, err = a.ValidatedReply.execute(ctx, reply)
		if err != nil {
			if callErr := new(badCallError); errors.As(err, &callErr) {
				return "", llmBadReply + err.Error(), nil
			}
			return "", "", err
		}
	}
	return reply, "", nil
}

const tokenCompressionInstruction = `
You are an expert technical assistant acting as a memory compressor.
Review the following execution history of an AI agent.

The first message begins with the original system instructions enclosed in
<system_instructions> tags, and then continues with the initial prompt.
These are provided for your information and will be preserved in the history
anyway, so DO NOT duplicate their contents in your summary.

Write a comprehensive and substantial summary of the current state of the workspace
and the investigation based on the SUBSEQUENT messages with all relevant details required
to continue work. Do NOT write a short summary.
Include:
1. A detailed list of what approaches have been tried so far and their results (including dead-ends).
2. The current hypotheses, theories, or active lines of investigation.
3. Any specific file paths, complete code snippets of relevant functions/structs/etc,
   or configuration values that are critical to remember.
4. Watch out for potential reasoning loops or repetitive tool calls and explicitly note them.

Write plain text in non-verbose manner: drop articles, filler words, pleasantries, hedging, etc;
sentence fragments are OK; keep technical terms/errors exact; keep code blocks unchanged.

You MUST provide the summary in your final response text. Do not use tools.
`

const tokenCompressionPrompt = `Task: Provide the comprehensive summary of the above execution history now.
Important: You must output the actual summary text in your final response. Do NOT use any tools.`

// We use a very low temperature for the compressor to ensure it acts as a strict,
// deterministic summarizer of facts without hallucinating or adding creative leaps.
const tokenCompressionTemperature = 0.1

func (a *agentSession) compressContext(
	ctx *Context, instruction string, splitIndex int) (*backend.Message, int, error) {
	// Lightweight config targeting the Flash model.
	temp := float32(tokenCompressionTemperature)
	cfg := &backend.GenerateConfig{
		Temperature: &temp,
		SystemInstruction: &backend.Message{
			Role:  backend.RoleUser,
			Parts: []backend.Part{{Text: tokenCompressionInstruction}},
		},
		ThinkingLevel: backend.ThinkingLevelHigh,
	}

	span := &trajectory.Span{
		Type:  trajectory.SpanLLM,
		Name:  a.Name + "-compressor",
		Model: string(backend.GoodBalancedModel),
	}
	if err := ctx.startSpan(span); err != nil {
		return nil, 0, err
	}

	var compressReq []llmMessage
	compressReq = append(compressReq, a.req[:splitIndex]...)
	if instruction != "" && len(compressReq) > 0 {
		msgCopy := *compressReq[0].content
		msgCopy.Parts = slices.Clone(msgCopy.Parts)
		compressReq[0].content = &msgCopy
		if len(compressReq[0].content.Parts) > 0 {
			compressReq[0].content.Parts[0] = backend.Part{
				Text: "<system_instructions>\n" + instruction +
					"\n</system_instructions>\n\n" + compressReq[0].content.Parts[0].Text,
			}
		}
	}

	// We append a final prompt to ensure the model knows it must summarize now,
	// rather than trying to continue the original conversation.
	compressReq = append(compressReq, llmMessage{content: &backend.Message{
		Role:  backend.RoleUser,
		Parts: []backend.Part{{Text: tokenCompressionPrompt}},
	}})

	var rawReq []*backend.Message
	for _, msg := range compressReq {
		rawReq = append(rawReq, msg.content)
	}

	resp, err := a.generateContent(ctx, cfg, rawReq, 0, backend.GoodBalancedModel, span)
	if err != nil {
		return nil, 0, ctx.finishSpan(span, err)
	}

	reply, _, respErr := a.parseResponse(resp, span)

	// We want the model to "think" for better reasoning during compression,
	// but we don't want to clutter the trajectory UI with those thoughts.
	span.Thoughts = ""

	if respErr != nil {
		return nil, 0, ctx.finishSpan(span, respErr)
	}

	reply = strings.TrimSpace(reply)
	if reply == "" {
		reply = "(The summarizer agent returned an empty summary)"
	}

	span.Reply = reply

	newSummary := &backend.Message{
		Role:  backend.RoleUser,
		Parts: []backend.Part{{Text: "Here is the summary of the previous execution history:\n\n" + reply}},
	}

	fmt.Printf("DEBUG compressContext finish: span.Model=%q\n", span.Model)
	return newSummary, span.OutputTokens, ctx.finishSpan(span, nil)
}

func (a *agentSession) maybeCompressContext(ctx *Context, instruction string, tokensToCompress int) (bool, error) {
	if a.compressTokens == 0 || tokensToCompress <= a.compressTokens {
		// Return existing state unchanged.
		return false, nil
	}

	preserveHistoryTokens := 20000

	// Find the split index to preserve up to preserveHistoryTokens.
	splitIndex := len(a.req)
	var suffixTokens int
	for i, msg := range slices.Backward(a.req) {
		suffixTokens += msg.tokenCount
		if suffixTokens > preserveHistoryTokens {
			break
		}
		// We only want to split at a message that came from the model (an LLM reply).
		if msg.content.Role == backend.RoleModel {
			splitIndex = i
		}
	}

	// If we couldn't find a suitable split, or if the split index is too small (e.g. 1),
	// we just compress everything up to len(a.req).
	if splitIndex <= 1 {
		splitIndex = len(a.req)
	}

	newSummary, summaryTokens, err := a.compressContext(ctx, instruction, splitIndex)
	if err != nil {
		return false, fmt.Errorf("context compression failed: %w", err)
	}

	// Truncate history to Anchor + Summary + Preserved Suffix.
	newReq := []llmMessage{a.req[0], {content: newSummary, tokenCount: summaryTokens}}
	if splitIndex < len(a.req) {
		newReq = append(newReq, a.req[splitIndex:]...)
	}
	a.req = newReq

	// Reset duplicate tool call history. Since the detailed conversation history
	// is discarded during compression, the LLM loses access to past raw tool
	// responses. We must reset the loop detection history to allow the LLM to
	// re-query tools if needed, preventing it from getting permanently stuck
	// when trying to re-fetch information that is no longer in its context.
	a.toolHistory = nil
	return true, nil
}

func (a *LLMAgent) config(ctx *Context) (*backend.GenerateConfig, string, string, map[string]Tool) {
	toolList := a.Tools
	if a.Outputs != nil {
		toolList = append(toolList, a.Outputs.tool)
	}
	toolMap := make(map[string]Tool)
	var tools []*backend.Tool
	for _, tool := range toolList {
		decl := tool.declaration()
		toolMap[decl.Name] = tool
		tools = append(tools, &backend.Tool{
			FunctionDeclarations: []*backend.FunctionDeclaration{decl}})
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
	return &backend.GenerateConfig{
		Temperature: new(taskParameters[a.TaskType]),
		SystemInstruction: &backend.Message{
			Role:  backend.RoleUser,
			Parts: []backend.Part{{Text: instruction}},
		},
		Tools: tools,
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
		ThinkingLevel: backend.ThinkingLevelHigh,
	}, instruction, prompt, toolMap
}

func (a *agentSession) callTools(ctx *Context, tools map[string]Tool, calls []*backend.FunctionCall) error {
	responses := &backend.Message{
		Role: backend.RoleUser,
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
			if err := a.recordAndCheckDuplicate(call); err != nil {
				toolErr = err
			} else {
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
		responses.Parts = append(responses.Parts, backend.Part{
			FunctionResponse: &backend.FunctionResponse{
				ID:       call.ID,
				Name:     call.Name,
				Response: span.Results,
			},
		})
		if isDuplicateErr(toolErr) {
			responses.Parts = append(responses.Parts, backend.Part{
				Text: fmt.Sprintf("SYSTEM WARNING: %s", toolErr.Error()),
			})
		}
		if toolErr == nil && a.Outputs != nil && tool == a.Outputs.tool {
			a.outputs = span.Results
		}
	}
	a.req = append(a.req, llmMessage{content: responses})
	return nil
}

func (a *LLMAgent) parseResponse(resp *backend.GenerateResponse, span *trajectory.Span) (
	reply string, calls []*backend.FunctionCall, err error) {
	if resp.UsageMetadata != nil {
		span.InputTokens = resp.UsageMetadata.InputTokens
		span.OutputTokens = resp.UsageMetadata.OutputTokens
		span.OutputThoughtsTokens = resp.UsageMetadata.OutputThoughtsTokens
	}
	for _, part := range resp.Parts {
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

const (
	maxLLMRetryIters = 100
	maxLLMBackoff    = 3 * time.Minute
)

func llmBackoffDuration(try int, baseDelay time.Duration) time.Duration {
	if baseDelay == 0 {
		return 0
	}
	backoff := baseDelay
	for range try {
		backoff *= 2
		if backoff >= maxLLMBackoff {
			return maxLLMBackoff
		}
	}
	return backoff
}

func (a *LLMAgent) generateContent(ctx *Context, cfg *backend.GenerateConfig,
	req []*backend.Message, candidate int, model backend.ModelCategory,
	span *trajectory.Span) (*backend.GenerateResponse, error) {
	// Don't alter the original object (that may affect request caching).
	cfgCopy := *cfg
	cfg = &cfgCopy

	resolvedModels := ctx.provider.ResolveModels(model)
	var lastErr error
	for _, m := range resolvedModels {
		if span != nil {
			span.Model = m
		}
		for try := 0; ; try++ {
			resp, err := a.generateContentCached(ctx, cfg, req, candidate, try, m)
			if retryErr := new(backend.RetryError); errors.As(err, &retryErr) {
				if try >= maxLLMRetryIters {
					lastErr = retryErr.Err
					break // stop retrying this model
				}
				delay := retryErr.Delay
				if retryErr.IsExponential {
					delay = llmBackoffDuration(try, retryErr.Delay)
				}
				ctx.sleep(delay)
				continue
			}
			if isOutputTokenOverflowError(err) &&
				cfg.ThinkingLevel != backend.ThinkingLevelMinimal {
				// Reduce amount of thinking and try again (thinking tokens are counted against output).
				// For non-thinking models this is effectively just a retry,
				// but that's fine, there is some chance that retry will succeed due to randomness,
				// or it will just fail after few retries.
				switch cfg.ThinkingLevel {
				case backend.ThinkingLevelHigh:
					cfg.ThinkingLevel = backend.ThinkingLevelMedium
				case backend.ThinkingLevelMedium:
					cfg.ThinkingLevel = backend.ThinkingLevelLow
				case backend.ThinkingLevelLow:
					cfg.ThinkingLevel = backend.ThinkingLevelMinimal
				default:
					return nil, fmt.Errorf("unexpected thinking level %v", cfg.ThinkingLevel)
				}
				continue
			}
			if err != nil {
				lastErr = err
				break // try next model
			}
			return resp, nil
		}
	}
	return nil, lastErr
}

func (a *LLMAgent) generateContentCached(ctx *Context, cfg *backend.GenerateConfig,
	req []*backend.Message, candidate, try int, model string) (*backend.GenerateResponse, error) {
	type Cached struct {
		Config  *backend.GenerateConfig
		Request []*backend.Message
		Reply   *backend.GenerateResponse
	}
	desc := fmt.Sprintf("model %v, config hash %v, request hash %v, candidate %v",
		model, hash.String(cfg), hash.String(req), candidate)
	cached, _, err := CacheObject(ctx, "llm", desc, func() (Cached, error) {
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
	if a.compressTokens == 0 {
		// Value chosen based on Gemini summarization of:
		// "Retrieval and Multi-Hop Reasoning in 1M-Token Context Windows: Evaluating LLMs on Classical Chinese Text"
		// (https://arxiv.org/pdf/2605.02173)
		// and "Gemini 3.1 Pro: The Complete Guide to Google's Latest AI Model"
		// (https://o-mega.ai/articles/gemini-3-1-pro-the-complete-guide-to-google-s-latest-ai-model-february-2026)
		// for gemini-3.1-pro model.
		// Note: here we assume the model has 1M input context.
		a.compressTokens = 150_000
	}
	ctx.requireNotEmpty(a.Name, "Name", a.Name)
	if a.ValidatedReply != nil {
		if a.Reply != "" {
			ctx.errorf(a.Name, "both Reply and ValidatedReply are specified")
		}
		a.ValidatedReply.verify(ctx)
		a.Reply = a.ValidatedReply.name
	}
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

func (a *agentSession) recordAndCheckDuplicate(call *backend.FunctionCall) error {
	a.toolHistory = append(a.toolHistory, toolCallRecord{Name: call.Name, Args: call.Args})
	if len(a.toolHistory) > maxHistorySize {
		a.toolHistory = a.toolHistory[1:] // Keep it a rolling window.
	}

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

	if repeats >= hardLoopDetectionLimit {
		return fmt.Errorf("agent got stuck in an infinite loop repeating tool call %q with args %+v",
			call.Name, call.Args)
	}

	if repeats == hardLoopDetectionLimit-1 {
		return newDuplicateCallError("CRITICAL: This is your %d-th attempt to call %q with args %+v. "+
			"You are stuck in a loop. You MUST change your search query, try a different tool, or proceed "+
			"to the next step with your current knowledge. The next duplicate attempt will force-terminate your execution.",
			repeats, call.Name, call.Args)
	}

	if repeats > limit {
		return newDuplicateCallError(llmDuplicateCallWarning)
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

type duplicateCallError struct {
	*badCallError
}

func (e *duplicateCallError) Unwrap() error {
	return e.badCallError
}

func newDuplicateCallError(message string, args ...any) error {
	return &duplicateCallError{&badCallError{fmt.Errorf(message, args...)}}
}

func isDuplicateErr(err error) bool {
	var dupErr *duplicateCallError
	return errors.As(err, &dupErr)
}
