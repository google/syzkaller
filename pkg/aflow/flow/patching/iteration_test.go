// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"context"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/require"
)

type dummyProvider struct{}

func (p *dummyProvider) Client(ctx context.Context) (backend.Client, error) { return nil, nil }

func (p *dummyProvider) Models(ctx context.Context) ([]string, error) { return nil, nil }

func (p *dummyProvider) ResolveModels(category backend.ModelCategory) []string {
	return []string{"model1"}
}

func (p *dummyProvider) Close() error { return nil }

func TestPatchIterationInputsBackwardCompatibility(t *testing.T) {
	flow := aflow.Flows[string(ai.WorkflowPatchIteration)]
	require.NotNil(t, flow)

	// Simulate existing job inputs where ReplyToComments is omitted.
	inputs := map[string]any{
		"AgentName":      "test-agent",
		"TargetOS":       "linux",
		"TargetArch":     "amd64",
		"Syzkaller":      "syzkaller",
		"Image":          "image",
		"Type":           "type",
		"VM":             []byte("{}"),
		"KernelConfig":   "config",
		"BugTitle":       "title",
		"CrashReport":    "report",
		"ReproOpts":      "opts",
		"ReproSyz":       "syz",
		"ReproC":         "c",
		"PatchHistory":   []ai.PatchHistoryEntry{},
		"BaseRepository": "repo",
		"BaseBranch":     "branch",
		"BaseCommit":     "commit",
		"StraceBin":      "strace",
	}

	onEvent := func(span *trajectory.Span) error { return nil }
	_, err := flow.Execute(context.Background(), inputs, aflow.ExecuteOptions{
		Provider: &dummyProvider{},
		OnEvent:  onEvent,
	})
	if err != nil {
		require.False(t, strings.Contains(err.Error(), "flow inputs are missing"),
			"expected checkInputs to succeed without ReplyToComments, got: %v", err)
	}
}

func TestPatchHistorySummarization(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	v1 := ai.PatchHistoryEntry{Version: 1, Description: "net: fix bug v1", Diff: "diff v1"}
	v2 := ai.PatchHistoryEntry{Version: 2, Description: "net: fix bug v2", Diff: "diff v2"}

	app1, err := appendDiscussionSummaryFunc(ctx, appendDiscussionSummaryArgs{
		CurrentPatchEntry:        v1,
		CurrentDiscussionSummary: "No reviewer comments.",
	})
	require.NoError(t, err)
	app2, err := appendDiscussionSummaryFunc(ctx, appendDiscussionSummaryArgs{
		CurrentPatchEntry:        v2,
		CurrentDiscussionSummary: "Reviewer asked to fix style.",
		SummarizedPatchHistory:   app1.SummarizedPatchHistory,
	})
	require.NoError(t, err)

	state := viewPatchHistoryState(app2)
	wantSummary := `Available patch versions:
v1: No reviewer comments.
v2: Reviewer asked to fix style.
Call this tool with a specific version number to see its diff and description.`

	res, err := viewPatchHistoryFunc(ctx, state, viewPatchHistoryArgs{Version: 0})
	require.NoError(t, err)
	require.Equal(t, wantSummary, res.Result)

	res, err = viewPatchHistoryFunc(ctx, state, viewPatchHistoryArgs{Version: 2})
	require.NoError(t, err)
	require.Equal(t, `Version: v2
Description:
net: fix bug v2

Diff:
diff v2

Discussion summary:
Reviewer asked to fix style.
`, res.Result)

	res, err = viewPatchHistoryFunc(ctx, state, viewPatchHistoryArgs{Version: 99})
	require.NoError(t, err)
	require.Equal(t, "Note: the specified version (v99) is not found.\n\n"+wantSummary, res.Result)
}
