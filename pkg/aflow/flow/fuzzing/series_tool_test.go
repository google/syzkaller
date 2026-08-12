// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolSeriesPatches(t *testing.T) {
	patches := []ai.SeriesPatch{
		{
			Seq:   0,
			Title: "net: tcp: fix RTO bugs",
			Body:  "Subject: [PATCH 0/2] net: tcp: fix RTO bugs\n\nCover letter description.\n",
		},
		{
			Seq:   1,
			Title: "net: tcp: fix retransmission timeout",
			Body: "Subject: [PATCH 1/2] net: tcp: fix retransmission timeout\n\n" +
				"Fix RTO calculation.\n\n--- a/net/ipv4/tcp.c\n+++ b/net/ipv4/tcp.c\n@@ -1 +1 @@\n-old\n+new\n",
		},
		{
			Seq:   2,
			Title: "net: tcp: optimize window calculation",
			Body: "Subject: [PATCH 2/2] net: tcp: optimize window calculation\n\n" +
				"Optimize window scale.\n",
		},
	}

	// Test listing mode with PatchNum=nil.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "The patch series contains 2 patches and a cover letter:")
			assert.Contains(t, res.Output, "[0] (Cover letter) net: tcp: fix RTO bugs")
			assert.Contains(t, res.Output, "[1] net: tcp: fix retransmission timeout")
			assert.Contains(t, res.Output, "[2] net: tcp: optimize window calculation")
		},
		"")

	// Test cover letter with PatchNum=0.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{PatchNum: new(0)},
		func(res seriesPatchesResult) {
			require.Equal(t, `Cover letter [0] net: tcp: fix RTO bugs:

Subject: [PATCH 0/2] net: tcp: fix RTO bugs

Cover letter description.`, res.Output)
		},
		"")

	// Test detail mode with valid PatchNum=1.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{PatchNum: new(1)},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "Patch [1] net: tcp: fix retransmission timeout:")
			assert.Contains(t, res.Output, "Fix RTO calculation.")
			assert.Contains(t, res.Output, "+new")
		},
		"")

	// Test detail mode with valid PatchNum=2.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{PatchNum: new(2)},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "Patch [2] net: tcp: optimize window calculation:")
			assert.Contains(t, res.Output, "Optimize window scale.")
		},
		"")

	// Test non-existent PatchNum (e.g. 5).
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{PatchNum: new(5)},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "The patch series contains 2 patches and a cover letter:")
			assert.Contains(t, res.Output, "[0] (Cover letter) net: tcp: fix RTO bugs")
			assert.Contains(t, res.Output, "PatchNum 5 was not found")
		},
		"")

	// Test empty patches slice.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: nil},
		seriesPatchesArgs{},
		func(res seriesPatchesResult) {
			assert.Equal(t, "No patches available in the series.", res.Output)
		},
		"")

	// Test patch truncation.
	longBody := strings.Repeat("line\n", 1100)
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: []ai.SeriesPatch{{Seq: 1, Title: "long patch", Body: longBody}}},
		seriesPatchesArgs{PatchNum: new(1)},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "[Output truncated: showing 1000 of 1100 lines]")
		},
		"")
}

func TestFormatPatchList(t *testing.T) {
	tests := []struct {
		name    string
		patches []ai.SeriesPatch
		want    string
	}{
		{
			name:    "empty",
			patches: nil,
			want:    "",
		},
		{
			name: "single patch without cover",
			patches: []ai.SeriesPatch{
				{Seq: 1, Title: "fix bug"},
			},
			want: "The patch series contains 1 patch:\n[1] fix bug",
		},
		{
			name: "multiple patches without cover",
			patches: []ai.SeriesPatch{
				{Seq: 1, Title: "fix bug 1"},
				{Seq: 2, Title: "fix bug 2"},
			},
			want: "The patch series contains 2 patches:\n[1] fix bug 1\n[2] fix bug 2",
		},
		{
			name: "single patch with cover",
			patches: []ai.SeriesPatch{
				{Seq: 0, Title: "cover"},
				{Seq: 1, Title: "fix bug"},
			},
			want: "The patch series contains 1 patch and a cover letter:\n[0] (Cover letter) cover\n[1] fix bug",
		},
		{
			name: "multiple patches with cover",
			patches: []ai.SeriesPatch{
				{Seq: 0, Title: "cover"},
				{Seq: 1, Title: "fix bug 1"},
				{Seq: 2, Title: "fix bug 2"},
			},
			want: "The patch series contains 2 patches and a cover letter:\n" +
				"[0] (Cover letter) cover\n" +
				"[1] fix bug 1\n" +
				"[2] fix bug 2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatPatchList(tt.patches)
			require.Equal(t, tt.want, got)
		})
	}
}
