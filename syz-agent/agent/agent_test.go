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
		cfg: &Config{},
		overQuotaModels: map[string]time.Time{
			"model-a": exhaustedAt,
		},
	}
	flow := &aflow.Flow{Models: []string{"model-a"}}

	s.resetModelQuota(exhaustedAt.Add(time.Minute))
	assert.True(t, s.modelOverQuota(flow))

	s.resetModelQuota(resetAt.Add(-time.Second))
	assert.True(t, s.modelOverQuota(flow))

	s.resetModelQuota(resetAt)
	assert.False(t, s.modelOverQuota(flow))
}
