// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

// LLMJudge evaluates a subagent's execution history periodically to detect
// loops, oscillation, or lack of progress and terminate the subagent early.
type LLMJudge struct {
	// Name of the judge agent (used for identification and logging).
	Name string
	// Model category used for the judge evaluation LLM.
	Model backend.ModelCategory
	// Instruction provides custom guidance or criteria for deciding whether to stop.
	Instruction string
	// MinIterations is the number of tool iterations to execute before judge
	// evaluations begin. Must be strictly greater than 0.
	MinIterations int
	// EvaluationInterval specifies how often (in iterations) the judge is invoked
	// after MinIterations is reached. Must be strictly greater than 0.
	EvaluationInterval int
	// PreserveToolResponses lists tool names whose execution responses should be
	// kept verbatim in the formatted history. Other tool responses are redacted to save tokens.
	PreserveToolResponses []string
	agent                 *LLMAgent
}

type JudgeOutputs struct {
	Stop   bool   `jsonschema:"Stop subagent if stuck in a loop, oscillating, or making no progress."`
	Reason string `jsonschema:"Reason for stopping or letting it continue."`
}

type JudgeExecutionResults struct {
	JudgeStopped  bool
	JudgeReason   string
	FailedHistory []*backend.Message
}

const (
	judgeStateStopped = "JudgeStopped"
	judgeStateReason  = "JudgeReason"
	judgeStateHistory = "History"
	judgeOutputStop   = "Stop"
	judgeOutputReason = "Reason"
)

func (j *LLMJudge) verify() error {
	if j.EvaluationInterval <= 0 {
		return fmt.Errorf("EvaluationInterval must be greater than 0")
	}
	if j.MinIterations <= 0 {
		return fmt.Errorf("MinIterations must be greater than 0")
	}
	j.agent = &LLMAgent{
		Name:          j.Name,
		Model:         j.Model,
		MaxIterations: 1,
		TaskType:      FormalReasoningTask,
		Outputs:       LLMOutputs[JudgeOutputs](),
		Instruction: j.Instruction + "\n\n" +
			"Analyze the provided history of the subagent and call set-results with Stop and Reason.",
		InitChatHistoryFunc: func(ctx *Context) ([]llmMessage, error) {
			history, _ := ctx.state[judgeStateHistory].([]llmMessage)
			return j.formatHistoryMessages(history), nil
		},
	}
	ctx := newVerifyContext()
	ctx.state[judgeStateHistory] = &varState{
		action: "judge inputs",
		typ:    reflect.TypeFor[[]llmMessage](),
		used:   false,
	}
	j.agent.verify(ctx)
	for _, state := range ctx.state {
		state.used = true
	}
	return ctx.finalize()
}

func (j *LLMJudge) Evaluate(ctx *Context, history []llmMessage) (JudgeOutputs, error) {
	oldState := ctx.state
	ctx.state = map[string]any{
		judgeStateHistory: history,
	}
	defer func() {
		ctx.state = oldState
	}()

	if err := j.agent.execute(ctx); err != nil {
		return JudgeOutputs{}, err
	}

	stop, _ := ctx.state[judgeOutputStop].(bool)
	reason, _ := ctx.state[judgeOutputReason].(string)

	return JudgeOutputs{Stop: stop, Reason: reason}, nil
}

// formatHistoryMessages converts subagent conversation history into messages
// suitable for the judge. Unlike context compression (which uses an LLM to
// generate a lossy summary), this deterministically preserves the complete
// sequence of tool calls and prompts while redacting large tool output
// payloads.
func (j *LLMJudge) formatHistoryMessages(history []llmMessage) []llmMessage {
	var messages []llmMessage
	for _, msg := range history {
		role := msg.content.Role
		var parts []backend.Part
		for _, part := range msg.content.Parts {
			if part.FunctionCall != nil {
				parts = append(parts, backend.Part{Text: fmt.Sprintf("Subagent called tool %s with args: %+v\n",
					part.FunctionCall.Name, part.FunctionCall.Args)})
			} else if part.FunctionResponse != nil {
				if slices.Contains(j.PreserveToolResponses, part.FunctionResponse.Name) {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Tool %s returned: %+v\n",
						part.FunctionResponse.Name, part.FunctionResponse.Response)})
				} else {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Tool %s returned: "+
						"[tool call result removed from conversation history]\n",
						part.FunctionResponse.Name)})
				}
			} else if part.Text != "" {
				if role == backend.RoleUser {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Subagent started with prompt:\n%s\n", part.Text)})
				} else {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Subagent thought/said:\n%s\n", part.Text)})
				}
			}
		}
		if len(parts) > 0 {
			messages = append(messages, llmMessage{
				content: &backend.Message{
					Role:  backend.RoleUser,
					Parts: parts,
				},
			})
		}
	}

	messages = append(messages, llmMessage{
		content: &backend.Message{
			Role:  backend.RoleUser,
			Parts: []backend.Part{{Text: "Analyze the subagent history above. Call set-results with Stop and Reason."}},
		},
	})
	return messages
}
