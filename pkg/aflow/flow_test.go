// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"fmt"
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
	inputs := map[string]any{
		"InFoo": 10,
		"InBar": "bar",
		"InBaz": "baz",
	}
	expectedOutputs := map[string]any{
		"AgentFoo":      42,
		"OutBar":        142,
		"OutBaz":        "baz",
		"OutFoo":        "hello, world!",
		"OutSwarm":      []string{"swarm candidate 1", "swarm candidate 2"},
		"SwarmInt":      []int{1, 2},
		"OutAggregator": "aggregated",
	}
	flows := make(map[string]*Flow)
	err := register[flowInputs, flowOutputs]("test", "description", flows, []*Flow{
		{
			Name: "flow",
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
					Model:       "model1",
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
				&LLMAgent{
					Name:        "swarm",
					Model:       "model2",
					Reply:       "OutSwarm",
					Candidates:  2,
					Outputs:     LLMOutputs[swarmOutputs](),
					Temperature: 0,
					Instruction: "Do something. {{.InBaz}}",
					Prompt:      "Prompt: {{.InBaz}}",
				},
				&LLMAgent{
					Name:        "aggregator",
					Model:       "model3",
					Reply:       "OutAggregator",
					Temperature: 0,
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
		generateContent: func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			replySeq++
			if replySeq < 4 {
				assert.Equal(t, model, "model1")
				assert.Equal(t, cfg.SystemInstruction, genai.NewContentFromText("You are smarty. baz"+
					llmOutputsInstruction, genai.RoleUser))
				assert.Equal(t, cfg.Temperature, genai.Ptr[float32](0))
				assert.Equal(t, len(cfg.Tools), 3)
				assert.Equal(t, cfg.Tools[0].FunctionDeclarations[0].Name, "tool1")
				assert.Equal(t, cfg.Tools[0].FunctionDeclarations[0].Description, "tool 1 description")
				assert.Equal(t, cfg.Tools[1].FunctionDeclarations[0].Name, "tool2")
				assert.Equal(t, cfg.Tools[1].FunctionDeclarations[0].Description, "tool 2 description")
				assert.Equal(t, cfg.Tools[2].FunctionDeclarations[0].Name, "set-results")
			} else if replySeq < 8 {
				assert.Equal(t, model, "model2")
				assert.Equal(t, cfg.SystemInstruction, genai.NewContentFromText("Do something. baz"+
					llmOutputsInstruction, genai.RoleUser))
				assert.Equal(t, len(cfg.Tools), 1)
				assert.Equal(t, cfg.Tools[0].FunctionDeclarations[0].Name, "set-results")
			} else {
				assert.Equal(t, model, "model3")
				assert.Equal(t, cfg.SystemInstruction, genai.NewContentFromText("Aggregate!", genai.RoleUser))
				assert.Equal(t, len(cfg.Tools), 0)
			}

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

			// dupl considers makeSwarmReply/makeSwarmResp duplicates
			// nolint:dupl
			makeSwarmReply := func(index int) *genai.Content {
				return &genai.Content{
					Role: string(genai.RoleModel),
					Parts: []*genai.Part{
						{
							FunctionCall: &genai.FunctionCall{
								ID:   fmt.Sprintf("id%v", index),
								Name: "set-results",
								Args: map[string]any{
									"SwarmInt": index,
									"SwarmStr": fmt.Sprintf("swarm%v", index),
								},
							},
						},
					}}
			}
			// nolint:dupl // dupl considers makeSwarmReply/makeSwarmResp duplicates
			makeSwarmResp := func(index int) *genai.Content {
				return &genai.Content{
					Role: string(genai.RoleUser),
					Parts: []*genai.Part{
						{
							FunctionResponse: &genai.FunctionResponse{
								ID:   fmt.Sprintf("id%v", index),
								Name: "set-results",
								Response: map[string]any{
									"SwarmInt": index,
									"SwarmStr": fmt.Sprintf("swarm%v", index),
								},
							},
						},
					}}
			}

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
			case 4, 6:
				index := (replySeq - 2) / 2
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText("Prompt: baz", genai.RoleUser),
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{Content: makeSwarmReply(index)}}}, nil
			case 5, 7:
				index := (replySeq - 3) / 2
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText("Prompt: baz", genai.RoleUser),
					makeSwarmReply(index),
					makeSwarmResp(index),
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{Content: &genai.Content{
							Role: string(genai.RoleUser),
							Parts: []*genai.Part{
								genai.NewPartFromText(fmt.Sprintf("swarm candidate %v", index))},
						}}}}, nil
			case 8:
				assert.Equal(t, req, []*genai.Content{
					genai.NewContentFromText(`Prompt: baz
#0: swarm candidate 1
#1: swarm candidate 2

#0: 1
#1: 2

#0: swarm1
#1: swarm2

`, genai.RoleUser),
				})
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{Content: &genai.Content{
							Role: string(genai.RoleUser),
							Parts: []*genai.Part{
								genai.NewPartFromText("aggregated")},
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
			Seq:         2,
			Nesting:     1,
			Type:        trajectory.SpanAgent,
			Name:        "smarty",
			Model:       "model1",
			Started:     startTime.Add(4 * time.Second),
			Instruction: "You are smarty. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz func-output",
		},
		{
			Seq:     3,
			Nesting: 2,
			Type:    trajectory.SpanLLM,
			Name:    "smarty",
			Model:   "model1",
			Started: startTime.Add(5 * time.Second),
		},
		{
			Seq:      3,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Model:    "model1",
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
			Model:   "model1",
			Started: startTime.Add(11 * time.Second),
		},
		{
			Seq:      6,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Model:    "model1",
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
			Model:   "model1",
			Started: startTime.Add(15 * time.Second),
		},
		{
			Seq:      8,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "smarty",
			Model:    "model1",
			Started:  startTime.Add(15 * time.Second),
			Finished: startTime.Add(16 * time.Second),
		},
		{
			Seq:         2,
			Nesting:     1,
			Type:        trajectory.SpanAgent,
			Name:        "smarty",
			Model:       "model1",
			Started:     startTime.Add(4 * time.Second),
			Finished:    startTime.Add(17 * time.Second),
			Instruction: "You are smarty. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz func-output",
			Reply:       "hello, world!",
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
			Seq:     10,
			Nesting: 1,
			Type:    trajectory.SpanAgentCandidates,
			Name:    "swarm",
			Started: startTime.Add(20 * time.Second),
		},
		{
			Seq:         11,
			Nesting:     2,
			Type:        trajectory.SpanAgent,
			Name:        "swarm",
			Model:       "model2",
			Started:     startTime.Add(21 * time.Second),
			Instruction: "Do something. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz",
		},
		{
			Seq:     12,
			Nesting: 3,
			Type:    trajectory.SpanLLM,
			Name:    "swarm",
			Model:   "model2",
			Started: startTime.Add(22 * time.Second),
		},
		{
			Seq:      12,
			Nesting:  3,
			Type:     trajectory.SpanLLM,
			Name:     "swarm",
			Model:    "model2",
			Started:  startTime.Add(22 * time.Second),
			Finished: startTime.Add(23 * time.Second),
		},
		{
			Seq:     13,
			Nesting: 3,
			Type:    trajectory.SpanTool,
			Name:    "set-results",
			Started: startTime.Add(24 * time.Second),
			Args: map[string]any{
				"SwarmInt": 1,
				"SwarmStr": "swarm1",
			},
		},
		{
			Seq:      13,
			Nesting:  3,
			Type:     trajectory.SpanTool,
			Name:     "set-results",
			Started:  startTime.Add(24 * time.Second),
			Finished: startTime.Add(25 * time.Second),
			Args: map[string]any{
				"SwarmInt": 1,
				"SwarmStr": "swarm1",
			},
			Results: map[string]any{
				"SwarmInt": 1,
				"SwarmStr": "swarm1",
			},
		},
		{
			Seq:     14,
			Nesting: 3,
			Type:    trajectory.SpanLLM,
			Name:    "swarm",
			Model:   "model2",
			Started: startTime.Add(26 * time.Second),
		},
		{
			Seq:      14,
			Nesting:  3,
			Type:     trajectory.SpanLLM,
			Name:     "swarm",
			Model:    "model2",
			Started:  startTime.Add(26 * time.Second),
			Finished: startTime.Add(27 * time.Second),
		},
		{
			Seq:         11,
			Nesting:     2,
			Type:        trajectory.SpanAgent,
			Name:        "swarm",
			Model:       "model2",
			Started:     startTime.Add(21 * time.Second),
			Finished:    startTime.Add(28 * time.Second),
			Instruction: "Do something. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz",
			Reply:       "swarm candidate 1",
			Results: map[string]any{
				"SwarmInt": 1,
				"SwarmStr": "swarm1",
			},
		},
		{
			Seq:         15,
			Nesting:     2,
			Type:        trajectory.SpanAgent,
			Name:        "swarm",
			Model:       "model2",
			Started:     startTime.Add(29 * time.Second),
			Instruction: "Do something. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz",
		},
		{
			Seq:     16,
			Nesting: 3,
			Type:    trajectory.SpanLLM,
			Name:    "swarm",
			Model:   "model2",
			Started: startTime.Add(30 * time.Second),
		},
		{
			Seq:      16,
			Nesting:  3,
			Type:     trajectory.SpanLLM,
			Name:     "swarm",
			Model:    "model2",
			Started:  startTime.Add(30 * time.Second),
			Finished: startTime.Add(31 * time.Second),
		},
		{
			Seq:     17,
			Nesting: 3,
			Type:    trajectory.SpanTool,
			Name:    "set-results",
			Started: startTime.Add(32 * time.Second),
			Args: map[string]any{
				"SwarmInt": 2,
				"SwarmStr": "swarm2",
			},
		},
		{
			Seq:      17,
			Nesting:  3,
			Type:     trajectory.SpanTool,
			Name:     "set-results",
			Started:  startTime.Add(32 * time.Second),
			Finished: startTime.Add(33 * time.Second),
			Args: map[string]any{
				"SwarmInt": 2,
				"SwarmStr": "swarm2",
			},
			Results: map[string]any{
				"SwarmInt": 2,
				"SwarmStr": "swarm2",
			},
		},
		{
			Seq:     18,
			Nesting: 3,
			Type:    trajectory.SpanLLM,
			Name:    "swarm",
			Model:   "model2",
			Started: startTime.Add(34 * time.Second),
		},
		{
			Seq:      18,
			Nesting:  3,
			Type:     trajectory.SpanLLM,
			Name:     "swarm",
			Model:    "model2",
			Started:  startTime.Add(34 * time.Second),
			Finished: startTime.Add(35 * time.Second),
		},
		{
			Seq:         15,
			Nesting:     2,
			Type:        trajectory.SpanAgent,
			Name:        "swarm",
			Model:       "model2",
			Started:     startTime.Add(29 * time.Second),
			Finished:    startTime.Add(36 * time.Second),
			Instruction: "Do something. baz" + llmOutputsInstruction,
			Prompt:      "Prompt: baz",
			Reply:       "swarm candidate 2",
			Results: map[string]any{
				"SwarmInt": 2,
				"SwarmStr": "swarm2",
			},
		},
		{
			Seq:      10,
			Nesting:  1,
			Type:     trajectory.SpanAgentCandidates,
			Name:     "swarm",
			Started:  startTime.Add(20 * time.Second),
			Finished: startTime.Add(37 * time.Second),
		},
		{
			Seq:         19,
			Nesting:     1,
			Type:        trajectory.SpanAgent,
			Name:        "aggregator",
			Model:       "model3",
			Started:     startTime.Add(38 * time.Second),
			Instruction: "Aggregate!",
			Prompt: `Prompt: baz
#0: swarm candidate 1
#1: swarm candidate 2

#0: 1
#1: 2

#0: swarm1
#1: swarm2

`,
		},
		{
			Seq:     20,
			Nesting: 2,
			Type:    trajectory.SpanLLM,
			Name:    "aggregator",
			Model:   "model3",
			Started: startTime.Add(39 * time.Second),
		},
		{
			Seq:      20,
			Nesting:  2,
			Type:     trajectory.SpanLLM,
			Name:     "aggregator",
			Model:    "model3",
			Started:  startTime.Add(39 * time.Second),
			Finished: startTime.Add(40 * time.Second),
		},
		{
			Seq:         19,
			Nesting:     1,
			Type:        trajectory.SpanAgent,
			Name:        "aggregator",
			Model:       "model3",
			Started:     startTime.Add(38 * time.Second),
			Finished:    startTime.Add(41 * time.Second),
			Instruction: "Aggregate!",
			Prompt: `Prompt: baz
#0: swarm candidate 1
#1: swarm candidate 2

#0: 1
#1: 2

#0: swarm1
#1: swarm2

`,
			Reply: "aggregated",
		},
		{
			Seq:      0,
			Nesting:  0,
			Type:     trajectory.SpanFlow,
			Name:     "test-flow",
			Started:  startTime.Add(1 * time.Second),
			Finished: startTime.Add(42 * time.Second),
			Results:  expectedOutputs,
		},
	}
	onEvent := func(span *trajectory.Span) error {
		require.NotEmpty(t, expected)
		require.Equal(t, span, expected[0])
		expected = expected[1:]
		return nil
	}
	res, err := flows["test-flow"].Execute(ctx, "", workdir, inputs, cache, onEvent)
	require.NoError(t, err)
	require.Equal(t, replySeq, 8)
	require.Equal(t, res, expectedOutputs)
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
		" field InBar is not present when converting map to aflow.flowInputs")
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
