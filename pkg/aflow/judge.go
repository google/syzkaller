// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

type LLMJudge struct {
	Name               string
	Model              backend.ModelCategory
	Instruction        string
	MinIterations      int
	EvaluationInterval int
	PreservedTools     []string
	agent              *LLMAgent
}

type JudgeOutputs struct {
	Stop   bool   `jsonschema:"Stop subagent if stuck in a loop, oscillating, or making no progress."`
	Reason string `jsonschema:"Reason for stopping or letting it continue."`
}

func (j *LLMJudge) verify() error {
	if j.EvaluationInterval <= 0 {
		return fmt.Errorf("EvaluationInterval must be greater than 0")
	}
	if j.MinIterations < 0 {
		return fmt.Errorf("MinIterations must be non-negative")
	}
	j.agent = &LLMAgent{
		Name:     j.Name,
		Model:    j.Model,
		TaskType: FormalReasoningTask,
		Outputs:  ValidatedLLMOutputs[JudgeOutputs, struct{}](nil),
		Instruction: j.Instruction + "\n\n" +
			"Analyze the provided history of the subagent and call set-results with Stop and Reason.",
		InitialHistoryProvider: func(ctx *Context) ([]llmMessage, error) {
			history, _ := ctx.state["History"].([]llmMessage)
			return j.formatHistoryMessages(history), nil
		},
		Reply: "JudgeReply",
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
	var outputs JudgeOutputs
	err := ctx.runWithState(map[string]any{"History": history}, func(ctx *Context) error {
		if err := j.agent.execute(ctx); err != nil {
			return err
		}
		stop, _ := ctx.state["Stop"].(bool)
		reason, _ := ctx.state["Reason"].(string)
		outputs = JudgeOutputs{Stop: stop, Reason: reason}
		return nil
	})
	if err != nil {
		return JudgeOutputs{}, err
	}
	return outputs, nil
}

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
				if slices.Contains(j.PreservedTools, part.FunctionResponse.Name) {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Tool %s returned: %+v\n",
						part.FunctionResponse.Name, part.FunctionResponse.Response)})
				} else {
					parts = append(parts, backend.Part{Text: fmt.Sprintf("Tool %s returned: [Omitted to save tokens]\n",
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
