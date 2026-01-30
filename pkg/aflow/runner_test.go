// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/genai"
)

var flagUpdate = flag.Bool("update", false, "update golden test files to match the actual execution")

// testFlow executes the provided test workflow by returning LLM replies from llmReplies.
// The result can be either a map[string]any with Outputs fields, or an error,
// if an error is expected as the result of the execution.
// llmReplies objects can be either *genai.Part, []*genai.Part, or an error.
// Requests sent to LLM are compared against "testdata/TestName.llm.json" file.
// Resulting trajectory is compared against "testdata/TestName.trajectory.json" file.
// If -update flag is provided, the golden testdata files are updated to match the actual execution.
func testFlow[Inputs, Outputs any](t *testing.T, inputs map[string]any, result any, root Action, llmReplies []any) {
	flows := make(map[string]*Flow)
	err := register[Inputs, Outputs]("test", "description", flows, []*Flow{{Root: root}})
	require.NoError(t, err)
	type llmRequest struct {
		Model   string
		Config  *genai.GenerateContentConfig `json:",omitempty"`
		Request []*genai.Content
	}
	var requests []llmRequest
	var stubTime time.Time
	var lastConfig genai.GenerateContentConfig
	generateContentStub := false
	stub := &stubContext{
		timeNow: func() time.Time {
			stubTime = stubTime.Add(time.Second)
			return stubTime
		},
		generateContent: func(model string, cfg *genai.GenerateContentConfig, req []*genai.Content) (
			*genai.GenerateContentResponse, error) {
			// Copy config and req slices, so that future changes to these objects
			// don't affect our stored requests.
			var storeCfg *genai.GenerateContentConfig
			if !reflect.DeepEqual(*cfg, lastConfig) {
				// Memorize config only if it has changed from the previous request.
				// Most of the time it's repeated for the same agent.
				lastConfig = *cfg
				cfgCopy := *cfg
				storeCfg = &cfgCopy
			}
			requests = append(requests, llmRequest{model, storeCfg, slices.Clone(req)})
			require.NotEmpty(t, llmReplies, "unexpected LLM call")
			reply := llmReplies[0]
			if cb, ok := reply.(func(string, *genai.GenerateContentConfig, []*genai.Content) (
				*genai.GenerateContentResponse, error)); ok {
				generateContentStub = true
				return cb(model, cfg, req)
			}
			llmReplies = llmReplies[1:]
			switch reply := reply.(type) {
			case error:
				return nil, reply
			case *genai.Part:
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{Content: &genai.Content{
						Role:  string(genai.RoleUser),
						Parts: []*genai.Part{reply},
					}}}}, nil
			case []*genai.Part:
				return &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{{Content: &genai.Content{
						Role:  string(genai.RoleUser),
						Parts: reply,
					}}}}, nil
			default:
				t.Fatalf("bad LLM reply type %T", reply)
				return nil, nil
			}
		},
	}
	var spans []trajectory.Span
	onEvent := func(span *trajectory.Span) error {
		spans = append(spans, *span)
		return nil
	}
	ctx := context.WithValue(context.Background(), stubContextKey, stub)
	workdir := t.TempDir()
	cache, err := newTestCache(t, filepath.Join(workdir, "cache"), 0, time.Now)
	require.NoError(t, err)
	if inputs == nil {
		inputs = map[string]any{}
	}
	got, err := flows["test"].Execute(ctx, "", workdir, inputs, cache, onEvent)
	switch result := result.(type) {
	case map[string]any:
		require.NoError(t, err)
		require.Equal(t, got, result)
	case string:
		require.Error(t, err)
		require.Equal(t, err.Error(), result)
	default:
		t.Fatalf("bad result type %T", result)
	}
	// We need to pass spans/requests via double marshal/unmarshal round-trip
	// b/c some values change during the first round-trip (int->float64, jsonschema).
	spansData, err := json.Marshal(spans)
	require.NoError(t, err)
	spans = nil
	require.NoError(t, json.Unmarshal(spansData, &spans))
	requestsData, err := json.Marshal(requests)
	require.NoError(t, err)
	requests = nil
	require.NoError(t, json.Unmarshal(requestsData, &requests))
	trajectoryFile := filepath.Join("testdata", t.Name()+".trajectory.json")
	requestsFile := filepath.Join("testdata", t.Name()+".llm.json")
	if *flagUpdate {
		require.NoError(t, osutil.WriteJSON(trajectoryFile, spans))
		if requests != nil {
			require.NoError(t, osutil.WriteJSON(requestsFile, requests))
		} else {
			os.Remove(requestsFile)
		}
	}
	wantSpans, err := osutil.ReadJSON[[]trajectory.Span](trajectoryFile)
	require.NoError(t, err)
	require.Equal(t, spans, wantSpans)
	if requests != nil {
		wantRequests, err := osutil.ReadJSON[[]llmRequest](requestsFile)
		require.NoError(t, err)
		require.Equal(t, requests, wantRequests)
	} else {
		require.False(t, osutil.IsExist(requestsFile))
	}
	require.True(t, len(llmReplies) == 0 || generateContentStub)
}

func testRegistrationError[Inputs, Outputs any](t *testing.T, expected string, root Action) {
	flows := map[string]*Flow{}
	err := register[Inputs, Outputs]("test", "description", flows, []*Flow{{Root: root}})
	require.Error(t, err)
	require.Equal(t, expected, err.Error())
}
