// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/assert"
)

func TestToolSeriesPatches(t *testing.T) {
	patches := []ai.SeriesPatch{
		{
			Seq:   0,
			Title: "net: tcp: fix RTO bugs",
			Body:  []byte("Subject: [PATCH 0/2] net: tcp: fix RTO bugs\n\nCover letter description.\n"),
		},
		{
			Seq:   1,
			Title: "net: tcp: fix retransmission timeout",
			Body: []byte("Subject: [PATCH 1/2] net: tcp: fix retransmission timeout\n\n" +
				"Fix RTO calculation.\n\n--- a/net/ipv4/tcp.c\n+++ b/net/ipv4/tcp.c\n@@ -1 +1 @@\n-old\n+new\n"),
		},
		{
			Seq:   2,
			Title: "net: tcp: optimize window calculation",
			Body: []byte("Subject: [PATCH 2/2] net: tcp: optimize window calculation\n\n" +
				"Optimize window scale.\n"),
		},
	}

	// Test listing mode with PatchNum=nil.
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "The patch series contains 3 patches:")
			assert.Contains(t, res.Output, "[0] net: tcp: fix RTO bugs")
			assert.Contains(t, res.Output, "[1] net: tcp: fix retransmission timeout")
			assert.Contains(t, res.Output, "[2] net: tcp: optimize window calculation")
		},
		"")

	// Test cover letter with PatchNum=0 (shows cover letter and list of patches).
	aflow.TestTool(t, ToolSeriesPatches,
		seriesPatchesState{Patches: patches},
		seriesPatchesArgs{PatchNum: new(0)},
		func(res seriesPatchesResult) {
			assert.Contains(t, res.Output, "Patch [0] net: tcp: fix RTO bugs:")
			assert.Contains(t, res.Output, "Cover letter description.")
			assert.Contains(t, res.Output, "The patch series contains 3 patches:")
			assert.Contains(t, res.Output, "[1] net: tcp: fix retransmission timeout")
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
			assert.Contains(t, res.Output, "The patch series contains 3 patches:")
			assert.Contains(t, res.Output, "[0] net: tcp: fix RTO bugs")
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
}
