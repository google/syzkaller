// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genai"
)

func TestWorkflow(t *testing.T) {
	type flowInputs struct {
		InFoo int
		InBar string
		InBaz string
	}
	type flowOutputs struct {
		OutFoo        string
		OutBar        int
		OutBaz        string
		AgentFoo      int
		OutSwarm      []string
		SwarmInt      []int
		OutAggregator string
	}
	type firstFuncInputs struct {
		InFoo int
		InBar string
	}
	type firstFuncOutputs struct {
		TmpFuncOutput string
		OutBar        int
	}
	type secondFuncInputs struct {
		AgentBar      string
		TmpFuncOutput string
		InFoo         int
	}
	type secondFuncOutputs struct {
		OutBaz string
	}
	type agentOutputs struct {
		AgentFoo int    `jsonschema:"foo"`
		AgentBar string `jsonschema:"bar"`
	}
	type tool1State struct {
		InFoo         int
		TmpFuncOutput string
	}
	type tool1Args struct {
		ArgFoo string `jsonschema:"foo"`
		ArgBar int    `jsonschema:"bar"`
	}
	type tool1Results struct {
		ResFoo    int    `jsonschema:"foo"`
		ResString string `jsonschema:"string"`
	}
	type tool2State struct {
		InFoo int
	}
	type tool2Args struct {
		ArgBaz int `jsonschema:"baz"`
	}
	type tool2Results struct {
		ResBaz int `jsonschema:"baz"`
	}
	type swarmOutputs struct {
		SwarmInt int    `jsonschema:"swarm-int"`
		SwarmStr string `jsonschema:"swarm-str"`
	}
	testFlow[flowInputs, flowOutputs](t,
		map[string]any{
			"InFoo": 10,
			"InBar": "bar",
			"InBaz": "baz",
		},
		map[string]any{
			"AgentFoo":      42,
			"OutBar":        142,
			"OutBaz":        "baz",
			"OutFoo":        "hello, world!",
			"OutSwarm":      []string{"swarm candidate 1", "swarm candidate 2"},
			"SwarmInt":      []int{1, 2},
			"OutAggregator": "aggregated",
		},
		Pipeline(
			NewFuncAction("func-action",
				func(ctx *Context, args firstFuncInputs) (firstFuncOutputs, error) {
					assert.Equal(t, args.InFoo, 10)
					assert.Equal(t, args.InBar, "bar")
					return firstFuncOutputs{
						TmpFuncOutput: "func-output",
						OutBar:        142,
					}, nil
				}),
			&LLMAgent{
				Name:        "smarty",
				Model:       "model1",
				Reply:       "OutFoo",
				Outputs:     LLMOutputs[agentOutputs](),
				TaskType:    FormalReasoningTask,
				Instruction: "You are smarty. {{.InBaz}}",
				Prompt:      "Prompt: {{.InBaz}} {{.TmpFuncOutput}}",
				Tools: []Tool{
					NewFuncTool("tool1", func(ctx *Context, state tool1State, args tool1Args) (tool1Results, error) {
						assert.Equal(t, state.InFoo, 10)
						assert.Equal(t, state.TmpFuncOutput, "func-output")
						assert.Equal(t, args.ArgFoo, "arg-foo")
						assert.Equal(t, args.ArgBar, 100)
						return tool1Results{
							ResFoo:    200,
							ResString: "res-string",
						}, nil
					}, "tool 1 description"),
					NewFuncTool("tool2", func(ctx *Context, state tool2State, args tool2Args) (tool2Results, error) {
						assert.Equal(t, state.InFoo, 10)
						assert.Equal(t, args.ArgBaz, 101)
						return tool2Results{
							ResBaz: 300,
						}, nil
					}, "tool 2 description"),
				},
			},
			NewFuncAction("another-action",
				func(ctx *Context, args secondFuncInputs) (secondFuncOutputs, error) {
					assert.Equal(t, args.AgentBar, "agent-bar")
					assert.Equal(t, args.TmpFuncOutput, "func-output")
					assert.Equal(t, args.InFoo, 10)
					return secondFuncOutputs{
						OutBaz: "baz",
					}, nil
				}),
			&LLMAgent{
				Name:        "swarm",
				Model:       "model2",
				Reply:       "OutSwarm",
				Candidates:  2,
				Outputs:     LLMOutputs[swarmOutputs](),
				TaskType:    FormalReasoningTask,
				Instruction: "Do something. {{.InBaz}}",
				Prompt:      "Prompt: {{.InBaz}}",
			},
			&LLMAgent{
				Name:        "aggregator",
				Model:       "model3",
				Reply:       "OutAggregator",
				TaskType:    FormalReasoningTask,
				Instruction: "Aggregate!",
				Prompt: `Prompt: {{.InBaz}}
{{range $i, $v := .OutSwarm}}#{{$i}}: {{$v}}
{{end}}
{{range $i, $v := .SwarmInt}}#{{$i}}: {{$v}}
{{end}}
{{range $i, $v := .SwarmStr}}#{{$i}}: {{$v}}
{{end}}
`,
			},
		),
		[]any{
			[]*genai.Part{
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id0",
						Name: "tool1",
						Args: map[string]any{
							"ArgFoo": "arg-foo",
							// Genai package will give us ints as float64
							// b/c they pass via json unmarshalling.
							// Test how we handle that.
							"ArgBar": float64(100),
						},
					},
				},
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id1",
						Name: "tool2",
						Args: map[string]any{
							"ArgBaz": 101.0,
						},
					},
				},
				{
					Text: "Some non-thoughts reply along with tool calls",
				},
				{
					Text:    "I am thinking I need to call some tools",
					Thought: true,
				},
			},
			[]*genai.Part{
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id2",
						Name: "set-results",
						Args: map[string]any{
							"AgentFoo": 42.0,
							"AgentBar": "agent-bar",
						},
					},
				},
				{
					Text:    "Completly blank.",
					Thought: true,
				},
				{
					Text:    "Whatever.",
					Thought: true,
				},
			},
			genai.NewPartFromText("hello, world!"),
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id1",
					Name: "set-results",
					Args: map[string]any{
						"SwarmInt": 1.0,
						"SwarmStr": "swarm1",
					},
				},
			},
			genai.NewPartFromText("swarm candidate 1"),
			&genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   "id2",
					Name: "set-results",
					Args: map[string]any{
						"SwarmInt": 2.0,
						"SwarmStr": "swarm2",
					},
				},
			},
			genai.NewPartFromText("swarm candidate 2"),
			genai.NewPartFromText("aggregated"),
		},
	)
}

func TestNoInputs(t *testing.T) {
	type flowInputs struct {
		InFoo int
		InBar string
	}
	type flowOutputs struct {
	}
	inputs := map[string]any{
		"InFoo": 10,
	}
	flows := make(map[string]*Flow)
	err := register[flowInputs, flowOutputs]("test", "description", flows, []*Flow{
		{
			Root: NewFuncAction("func-action",
				func(ctx *Context, args flowInputs) (flowOutputs, error) {
					return flowOutputs{}, nil
				}),
		},
	})
	require.NoError(t, err)
	stub := &stubContext{
		generateContent: func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			return nil, nil
		},
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	workdir := t.TempDir()
	cache, err := newTestCache(t, filepath.Join(workdir, "cache"), 0, stub.timeNow)
	require.NoError(t, err)
	onEvent := func(span *trajectory.Span) error { return nil }
	_, err = flows["test"].Execute(ctx, "", workdir, inputs, cache, onEvent)
	require.Equal(t, err.Error(), "flow inputs are missing:"+
		" aflow.flowInputs: field \"InBar\" is not present when converting map")
}

func TestQuotaResetTime(t *testing.T) {
	type Test struct {
		when  time.Time
		reset time.Time
	}
	testLoc := time.FixedZone("+4h", 4*60*60) // seconds east of UTC
	tests := []Test{
		{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2000, 1, 1, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 0, 0, 0, 0, testLoc), time.Date(2000, 1, 1, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 8, 0, 0, 0, time.UTC), time.Date(2000, 1, 1, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 8, 0, 0, 0, testLoc), time.Date(2000, 1, 1, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 9, 0, 0, 0, time.UTC), time.Date(2000, 1, 2, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 9, 0, 0, 0, testLoc), time.Date(2000, 1, 1, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 13, 0, 0, 0, time.UTC), time.Date(2000, 1, 2, 8, 5, 0, 0, time.UTC)},
		{time.Date(2000, 1, 1, 13, 0, 0, 0, testLoc), time.Date(2000, 1, 2, 8, 5, 0, 0, time.UTC)},
	}
	for _, test := range tests {
		got := QuotaResetTime(test.when)
		assert.Equal(t, test.reset, got, "when: %v", test.when)
	}
}

func TestToolMisbehavior(t *testing.T) {
	type flowOutputs struct {
		Reply            string
		AdditionalOutput int
	}
	type tool1Args struct {
		Tool1Arg string `jsonschema:"arg"`
	}
	type tool2Args struct {
		Tool2Arg int `jsonschema:"arg"`
	}
	type tool2Results struct {
		Result int `jsonschema:"arg"`
	}
	testFlow[struct{}, flowOutputs](t, nil,
		map[string]any{
			"Reply":            "Finally done",
			"AdditionalOutput": 2,
		},
		Pipeline(
			&LLMAgent{
				Name:     "smarty",
				Model:    "model",
				TaskType: FormalReasoningTask,
				Reply:    "Reply",

				Outputs: LLMOutputs[struct {
					AdditionalOutput int `jsonschema:"arg"`
				}](),
				Instruction: "Do something!",
				Prompt:      "Prompt",
				Tools: []Tool{
					NewFuncTool("tool1", func(ctx *Context, state struct{}, args tool1Args) (struct{}, error) {
						return struct{}{}, nil
					}, "tool description"),
					NewFuncTool("tool2", func(ctx *Context, state struct{}, args tool2Args) (tool2Results, error) {
						return tool2Results{42}, nil
					}, "tool description"),
				},
			},
		),
		[]any{
			[]*genai.Part{
				// This tool call is OK, and the tool must be called.
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id1",
						Name: "tool1",
						Args: map[string]any{
							"Tool1Arg": "string",
						},
					},
				},
				// Incorrect argument type.
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id2",
						Name: "tool2",
						Args: map[string]any{
							"Tool2Arg": "string-instead-of-int",
						},
					},
				},
				// Missing argument.
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id3",
						Name: "tool2",
					},
				},
				// Excessive argument.
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id4",
						Name: "tool2",
						Args: map[string]any{
							"Tool2Arg":  0.0,
							"Tool2Arg2": 100.0,
						},
					},
				},
				// Tool that does not exist.
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id5",
						Name: "tool3",
						Args: map[string]any{
							"Arg": 0,
						},
					},
				},
				// Wrong arg for set-results (should not count as it was called).
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id6",
						Name: "set-results",
						Args: map[string]any{
							"WrongArg": 0,
						},
					},
				},
			},
			// Now it tries to provide the final result w/o calling set-results (successfully).
			genai.NewPartFromText("I am done"),
			[]*genai.Part{
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id1",
						Name: "set-results",
						Args: map[string]any{
							"AdditionalOutput": 1,
						},
					},
				},
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "id2",
						Name: "set-results",
						Args: map[string]any{
							"AdditionalOutput": 2,
						},
					},
				},
			},
			// LLM tries to get away w/o answering anything.
			genai.NewPartFromText(""),
			genai.NewPartFromText("Finally done"),
		},
	)
}
