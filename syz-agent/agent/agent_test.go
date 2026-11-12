// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/assert"
)

func TestResetModelQuota(t *testing.T) {
	exhaustedAt := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	resetAt := aflow.QuotaResetTime(exhaustedAt)

	s := &Server{
		cfg: &Config{DefaultBackend: backendGemini},
		overQuotaModels: map[modelQuota]time.Time{
			{backendGemini, aflow.CoreModel}: exhaustedAt,
		},
	}
	flow := &aflow.Flow{Models: []aflow.ModelCategory{aflow.CoreModel}}

	s.resetModelQuota(exhaustedAt.Add(time.Minute))
	assert.True(t, s.modelOverQuota(flow))

	s.resetModelQuota(resetAt.Add(-time.Second))
	assert.True(t, s.modelOverQuota(flow))

	s.resetModelQuota(resetAt)
	assert.False(t, s.modelOverQuota(flow))
}

func TestModelOverQuota(t *testing.T) {
	flows := []*aflow.Flow{
		{Name: "core", Models: []aflow.ModelCategory{aflow.CoreModel, aflow.LightweightModel}},
		{Name: "deep", Models: []aflow.ModelCategory{aflow.DeepReasoningModel, aflow.LightweightModel}},
		{Name: "vertex", Models: []aflow.ModelCategory{aflow.CoreModel, aflow.LightweightModel}},
	}
	tests := []struct {
		model string
		want  []string
	}{
		{"", []string{"core"}},
		// With a model override, all model categories resolve to the same model.
		{"override", []string{"core", "deep"}},
	}
	for _, test := range tests {
		s := &Server{
			cfg: &Config{
				Model:            test.model,
				DefaultBackend:   backendGemini,
				WorkflowBackends: map[string]string{"vertex": backendVertex},
			},
			overQuotaModels: map[modelQuota]time.Time{
				{backendGemini, aflow.CoreModel}: time.Now(),
			},
		}
		var got []string
		for _, flow := range flows {
			if s.modelOverQuota(flow) {
				got = append(got, flow.Name)
			}
		}
		assert.Equal(t, test.want, got, "model override %q", test.model)
	}
}
