// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"reflect"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

type LLMJudge struct {
	Name               string
	Model              backend.ModelCategory
	Instruction        string
	MinIterations      int
	EvaluationInterval int
	agent              *LLMAgent
}

type JudgeOutputs struct {
	Stop   bool   `jsonschema:"Stop subagent if stuck in a loop, oscillating, or making no progress."`
	Reason string `jsonschema:"Reason for stopping or letting it continue."`
}

func (j *LLMJudge) verify() error {
	j.agent = &LLMAgent{
		Name:          j.Name,
		Model:         j.Model,
		MaxIterations: 1,
		TaskType:      FormalReasoningTask,
		Outputs:       LLMOutputs[JudgeOutputs](),
		Instruction: j.Instruction + "\n\n" +
			"Analyze the provided history of the subagent and call set-results with Stop and Reason.",
		InitialMessages: func(ctx *Context) ([]llmMessage, error) {
			history, _ := ctx.state["History"].([]llmMessage)
			return FormatHistoryMessagesForJudge(history), nil
		},
	}
	ctx := newVerifyContext()
	ctx.state["History"] = &varState{
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
		"History": history,
	}
	defer func() {
		ctx.state = oldState
	}()

	if err := j.agent.execute(ctx); err != nil {
		return JudgeOutputs{}, err
	}

	stop, _ := ctx.state["Stop"].(bool)
	reason, _ := ctx.state["Reason"].(string)

	return JudgeOutputs{Stop: stop, Reason: reason}, nil
}

func FormatHistoryMessagesForJudge(history []llmMessage) []llmMessage {
	var messages []llmMessage
	for _, msg := range history {
		role := msg.content.Role
		var parts []backend.Part
		for _, part := range msg.content.Parts {
			if part.FunctionCall != nil {
				parts = append(parts, backend.Part{Text: fmt.Sprintf("Subagent called tool %s with args: %+v\n",
					part.FunctionCall.Name, part.FunctionCall.Args)})
			} else if part.FunctionResponse != nil {
				if part.FunctionResponse.Name == "execute-seed" {
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
				tokenCount: msg.tokenCount,
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
