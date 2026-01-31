// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"testing"

	"google.golang.org/genai"
)

func TestToolErrors(t *testing.T) {
	type flowOutputs struct {
		Reply string
	}
	type toolArgs struct {
		CallError bool `jsonschema:"call error"`
	}
	testFlow[struct{}, flowOutputs](t, nil,
		"tool faulty failed: error: hard error\nargs: map[CallError:false]",
		&LLMAgent{
			Name:        "smarty",
			Model:       "model",
			Reply:       "Reply",
			TaskType:    FormalReasoningTask,
			Instruction: "Do something!",
			Prompt:      "Prompt",
			Tools: []Tool{
				NewFuncTool("faulty", func(ctx *Context, state struct{}, args toolArgs) (struct{}, error) {
					if args.CallError {
						return struct{}{}, BadCallError("you are wrong")
					}
					return struct{}{}, errors.New("hard error")
				}, "tool 1 description"),
			},
		},
		[]any{
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id0",
					Name: "faulty",
					Args: map[string]any{
						"CallError": true,
					},
				},
			},
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id0",
					Name: "faulty",
					Args: map[string]any{
						"CallError": false,
					},
				},
			},
		},
	)
}
