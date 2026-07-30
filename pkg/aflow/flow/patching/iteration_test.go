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
