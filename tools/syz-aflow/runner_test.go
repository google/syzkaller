// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/require"
)

func TestAppendOrUpdateSpan(t *testing.T) {
	var spans []*trajectory.Span

	// Add span with Seq 0.
	s0 := &trajectory.Span{Seq: 0, Name: "start_0"}
	spans = appendOrUpdateSpan(spans, s0)
	require.Equal(t, []*trajectory.Span{s0}, spans)

	// Add span with Seq 2 (out of order, skipping Seq 1).
	s2 := &trajectory.Span{Seq: 2, Name: "start_2"}
	spans = appendOrUpdateSpan(spans, s2)
	require.Equal(t, []*trajectory.Span{s0, nil, s2}, spans)

	// Fill in span with Seq 1.
	s1 := &trajectory.Span{Seq: 1, Name: "start_1"}
	spans = appendOrUpdateSpan(spans, s1)
	require.Equal(t, []*trajectory.Span{s0, s1, s2}, spans)

	// Update span with Seq 0 on finish.
	s0Updated := &trajectory.Span{Seq: 0, Name: "finish_0"}
	spans = appendOrUpdateSpan(spans, s0Updated)
	require.Equal(t, []*trajectory.Span{s0Updated, s1, s2}, spans)
}
