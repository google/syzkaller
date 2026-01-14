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
		OutFoo   string
		OutBar   int
		OutBaz   string
		AgentFoo int
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
	inputs := map[string]any{
		"InFoo": 10,
		"InBar": "bar",
		"InBaz": "baz",
	}
	flows := make(map[string]*Flow)
	err := register[flowInputs, flowOutputs]("test", "description", flows, []*Flow{
		{
			Name:  "flow",
			Model: "model",
			Root: NewPipeline(
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
					Reply:       "OutFoo",
					Outputs:     LLMOutputs[agentOutputs](),
					Temperature: 0,
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
			),
		},
	})
	require.NoError(t, err)
	var startTime time.Time
	stubTime := startTime
	replySeq := 0
	stub := &stubContext{
		timeNow: func() time.Time {
			stubTime = stubTime.Add(time.Second)
			return stubTime
		},
		generateContent: func(cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			assert.Equal(t, cfg.SystemInstruction, genai.NewContentFromText(`You are smarty. baz

Use set-results tool to provide results of the analysis.
It must be called exactly once before the final reply.
Ignore results of this tool.
`, genai.RoleUser))
			assert.Equal(t, cfg.Temperature, genai.Ptr[float32](0))
			assert.Equal(t, len(cfg.Tools), 3)
			assert.Equal(t, cfg.Tools[0].FunctionDeclarations[0].Name, "tool1")
			assert.Equal(t, cfg.Tools[0].FunctionDeclarations[0].Description, "tool 1 description")
			assert.Equal(t, cfg.Tools[1].FunctionDeclarations[0].Name, "tool2")
			assert.Equal(t, cfg.Tools[1].FunctionDeclarations[0].Description, "tool 2 description")
			assert.Equal(t, cfg.Tools[2].FunctionDeclarations[0].Name, "set-results")

			reply1 := &genai.Content{
				Role: string(genai.RoleModel),
				Parts: []*genai.Part{
					{
						FunctionCall: &genai.FunctionCall{
							ID:   "id0",
							Name: "tool1",
							Args: map[string]any{
								"ArgFoo": "arg-foo",
								"ArgBar": 100,
							},
						},
					},
					{
						FunctionCall: &genai.FunctionCall{
							ID:   "id1",
							Name: "tool2",
							Args: map[string]any{
								"ArgBaz": 101,
							},
						},
					},
					{
						Text:    "I am thinking I need to call some tools",
						Thought: true,
					},
				}}
			resp1 := &genai.Content{
				Role: string(genai.RoleUser),
				Parts: []*genai.Part{
					{
						FunctionResponse: &genai.FunctionResponse{
							ID:   "id0",
							Name: "tool1",
							Response: map[string]any{
								"ResFoo":    200,
								"ResString": "res-string",
							},
						},
					},
					{
						FunctionResponse: &genai.FunctionResponse{
							ID:   "id1",
							Name: "tool2",
							Response: map[string]any{
								"ResBaz": 300,
							},
						},
					},
				}}
			reply2 := &genai.Content{
				Role: string(genai.RoleModel),
				Parts: []*genai.Part{
					{
						FunctionCall: &genai.FunctionCall{
							ID:   "id2",
							Name: "set-results",
							Args: map[string]any{
								"AgentFoo": 42,
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
				}}
			resp2 := &genai.Content{
				Role: string(genai.RoleUser),
				Parts: []*genai.Part{
					{
						FunctionResponse: &genai.FunctionResponse{
							ID:   "id2",
							Name: "set-results",
							Response: map[string]any{
								"AgentFoo": 42,
								"AgentBar": "agent-bar",
							},
						},
					},
				}}

			replySeq++
			switch replySeq {
			case 1:
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText("Prompt: baz func-output", genai.RoleUser),
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{Content: reply1}}}, nil
			case 2:
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText("Prompt: baz func-output", genai.RoleUser),
					reply1,
					resp1,
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{Content: reply2}}}, nil
			case 3:
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText("Prompt: baz func-output", genai.RoleUser),
					reply1,
					resp1,
					reply2,
					resp2,
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{Content: &genai.Content{
							Role: string(genai.RoleUser),
							Parts: []*genai.Part{
								genai.NewPartFromText("hello, world!")},
						}}}}, nil

			default:
				t.Fatal("unexpected LLM calls")
				return nil, nil
			}
		},
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	workdir := t.TempDir()
	cache, err := newTestCache(t, filepath.Join(workdir, "cache"), 0, stub.timeNow)
	require.NoError(t, err)
	// nolint: dupl
	expected := []*trajectory.Span{
		{
			Seq:     0,
			Nesting: 0,
			Type:    trajectory.SpanFlow,
			Name:    "test-flow",
			Started: startTime.Add(1 * time.Second),
		},
		{
			Seq:     1,
			Nesting: 1,
			Type:    trajectory.SpanAction,
			Name:    "func-action",
			Started: startTime.Add(2 * time.Second),
		},
		{
			Seq:      1,
			Nesting:  1,
			Type:     trajectory.SpanAction,
			Name:     "func-action",
			Started:  startTime.Add(2 * time.Second),
			Finished: startTime.Add(3 * time.Second),
			Results: map[string]any{
				"TmpFuncOutput": "func-output",
				"OutBar":        142,
			},
		},
		{
			Seq:     2,
			Nesting: 1,
			Type:    trajectory.SpanAgent,
			Name:    "smarty",
			Started: startTime.Add(4 * time.Second),
			Instruction: `You are smarty. baz

Use set-results tool to provide results of the analysis.
It must be called exactly once before the final reply.
Ignore results of this tool.
`,
			Prompt: "Prompt: baz func-output",
		},
		{
			Seq:     3,
			Nesting: 2,
			Type:    trajectory.SpanLLM,
			Name:    "smarty",
			Started: startTime.Add(5 * time.Second),
		},
		{
			Seq:      3,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Started:  startTime.Add(5 * time.Second),
			Finished: startTime.Add(6 * time.Second),
			Thoughts: "I am thinking I need to call some tools",
		},
		{
			Seq:     4,
			Nesting: 2,
			Type:    trajectory.SpanTool,
			Name:    "tool1",
			Started: startTime.Add(7 * time.Second),
			Args: map[string]any{
				"ArgBar": 100,
				"ArgFoo": "arg-foo",
			},
		},
		{
			Seq:      4,
			Nesting:  2,
			Type:     trajectory.SpanTool,
			Name:     "tool1",
			Started:  startTime.Add(7 * time.Second),
			Finished: startTime.Add(8 * time.Second),
			Args: map[string]any{
				"ArgBar": 100,
				"ArgFoo": "arg-foo",
			},
			Results: map[string]any{
				"ResFoo":    200,
				"ResString": "res-string",
			},
		},
		{
			Seq:     5,
			Nesting: 2,
			Type:    trajectory.SpanTool,
			Name:    "tool2",
			Started: startTime.Add(9 * time.Second),
			Args: map[string]any{
				"ArgBaz": 101,
			},
		},
		{
			Seq:      5,
			Nesting:  2,
			Type:     trajectory.SpanTool,
			Name:     "tool2",
			Started:  startTime.Add(9 * time.Second),
			Finished: startTime.Add(10 * time.Second),
			Args: map[string]any{
				"ArgBaz": 101,
			},
			Results: map[string]any{
				"ResBaz": 300,
			},
		},
		{
			Seq:     6,
			Nesting: 2,
			Type:    trajectory.SpanLLM,
			Name:    "smarty",
			Started: startTime.Add(11 * time.Second),
		},
		{
			Seq:      6,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Started:  startTime.Add(11 * time.Second),
			Finished: startTime.Add(12 * time.Second),
			Thoughts: "Completly blank.Whatever.",
		},
		{
			Seq:     7,
			Nesting: 2,
			Type:    trajectory.SpanTool,
			Name:    "set-results",
			Started: startTime.Add(13 * time.Second),
			Args: map[string]any{
				"AgentBar": "agent-bar",
				"AgentFoo": 42,
			},
		},
		{
			Seq:      7,
			Nesting:  2,
			Type:     trajectory.SpanTool,
			Name:     "set-results",
			Started:  startTime.Add(13 * time.Second),
			Finished: startTime.Add(14 * time.Second),
			Args: map[string]any{
				"AgentBar": "agent-bar",
				"AgentFoo": 42,
			},
			Results: map[string]any{
				"AgentBar": "agent-bar",
				"AgentFoo": 42,
			},
		},
		{
			Seq:     8,
			Nesting: 2,
			Type:    trajectory.SpanLLM,
			Name:    "smarty",
			Started: startTime.Add(15 * time.Second),
		},
		{
			Seq:      8,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Started:  startTime.Add(15 * time.Second),
			Finished: startTime.Add(16 * time.Second),
		},
		{
			Seq:      2,
			Nesting:  1,
			Type:     trajectory.SpanAgent,
			Name:     "smarty",
			Started:  startTime.Add(4 * time.Second),
			Finished: startTime.Add(17 * time.Second),
			Instruction: `You are smarty. baz

Use set-results tool to provide results of the analysis.
It must be called exactly once before the final reply.
Ignore results of this tool.
`,
			Prompt: "Prompt: baz func-output",
			Reply:  "hello, world!",
			Results: map[string]any{
				"AgentBar": "agent-bar",
				"AgentFoo": 42,
			},
		},
		{
			Seq:     9,
			Nesting: 1,
			Type:    trajectory.SpanAction,
			Name:    "another-action",
			Started: startTime.Add(18 * time.Second),
		},
		{
			Seq:      9,
			Nesting:  1,
			Type:     trajectory.SpanAction,
			Name:     "another-action",
			Started:  startTime.Add(18 * time.Second),
			Finished: startTime.Add(19 * time.Second),
			Results: map[string]any{
				"OutBaz": "baz",
			},
		},
		{
			Seq:      0,
			Nesting:  0,
			Type:     trajectory.SpanFlow,
			Name:     "test-flow",
			Started:  startTime.Add(1 * time.Second),
			Finished: startTime.Add(20 * time.Second),
			Results: map[string]any{
				"AgentFoo": 42,
				"OutBar":   142,
				"OutBaz":   "baz",
				"OutFoo":   "hello, world!",
			},
		},
	}
	onEvent := func(span *trajectory.Span) error {
		require.NotEmpty(t, expected)
		require.Equal(t, span, expected[0])
		expected = expected[1:]
		return nil
	}
	res, err := flows["test-flow"].Execute(ctx, "model", workdir, inputs, cache, onEvent)
	require.NoError(t, err)
	require.Equal(t, res, map[string]any{
		"OutFoo":   "hello, world!",
		"OutBar":   142,
		"OutBaz":   "baz",
		"AgentFoo": 42,
	})
	require.Empty(t, expected)
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
			Model: "model",
			Root: NewFuncAction("func-action",
				func(ctx *Context, args flowInputs) (flowOutputs, error) {
					return flowOutputs{}, nil
				}),
		},
	})
	require.NoError(t, err)
	stub := &stubContext{
		generateContent: func(cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			return nil, nil
		},
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	workdir := t.TempDir()
	cache, err := newTestCache(t, filepath.Join(workdir, "cache"), 0, stub.timeNow)
	require.NoError(t, err)
	onEvent := func(span *trajectory.Span) error { return nil }
	_, err = flows["test"].Execute(ctx, "model", workdir, inputs, cache, onEvent)
	require.Equal(t, err.Error(), "flow inputs are missing:"+
		" field InBar is not present when converting map to aflow.flowInputs")
}
