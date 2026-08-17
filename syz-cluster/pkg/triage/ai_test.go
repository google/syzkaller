// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"context"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingTriageWorkflowRegistered(t *testing.T) {
	flow := aflow.Flows[string(ai.WorkflowFindingTriage)]
	require.NotNil(t, flow, "WorkflowFindingTriage must be registered in aflow.Flows")
}

func TestNewAIClientNoAPIKey(t *testing.T) {
	ctx := context.Background()
	cfg := &app.AppConfig{
		AI: &app.AIConfig{},
	}
	tracer := &debugtracer.NullTracer{}
	client, err := NewAIClient(ctx, cfg, tracer)
	assert.Error(t, err)
	assert.Nil(t, client)
}
