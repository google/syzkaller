// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSectionHashes(t *testing.T) {
	hashes := build.SectionHashes{
		Text: map[string]string{"A": "1"},
		Data: map[string]string{"B": "2"},
	}

	jsonData, err := json.Marshal(hashes)
	require.NoError(t, err)

	file, err := osutil.WriteTempFile(jsonData)
	require.NoError(t, err)
	defer os.Remove(file)

	fromFile, err := readSectionHashes(file)
	require.NoError(t, err)
	assert.Equal(t, hashes, fromFile)
}

// nolint: dupl
func TestShouldSkipFuzzing(t *testing.T) {
	t.Run("one empty", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			build.SectionHashes{},
			build.SectionHashes{
				Text: map[string]string{"A": "1"},
			},
		))
	})
	t.Run("equal symbols", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
		))
	})
	t.Run("ignore known variables", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "raw_data": "A", "vermagic": "A"},
			},
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "raw_data": "B", "vermagic": "B"},
			},
		))
	})
	t.Run("same len, different hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
			},
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "different"},
			},
		))
		assert.False(t, shouldSkipFuzzing(
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "different"},
			},
		))
	})
	t.Run("different len, same hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
			},
			build.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2", "C": "new"},
			},
		))
	})
}

func TestBugTitleRe(t *testing.T) {
	assert.True(t, titleMatchesFilter(&api.FuzzConfig{}, "any title must match"))
	assert.True(t, titleMatchesFilter(&api.FuzzConfig{
		BugTitleRe: `^Prefix:`,
	}, "Prefix: must pass"))
	assert.False(t, titleMatchesFilter(&api.FuzzConfig{
		BugTitleRe: `^Prefix:`,
	}, "Without prefix"))
}

func TestFilterFindingCandidates(t *testing.T) {
	bugs := []manager.DiffBug{
		{
			Title:   "candidate crash 1",
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report1"},
		},
		{
			Title:   "reproduced crash",
			Base:    manager.DiffBugInfo{NotCrashed: true},
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report_repro"},
		},
		{
			Title:   "crash on base too",
			Base:    manager.DiffBugInfo{Crashes: 2},
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report2"},
		},
		{
			Title:   "crash without report",
			Patched: manager.DiffBugInfo{Crashes: 5, Report: ""},
		},
		{
			Title:   "ignored status crash",
			Status:  manager.DiffBugStatusIgnored,
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report3"},
		},
	}

	candidates := filterFindingCandidates(bugs)
	require.Len(t, candidates, 1)
	assert.Equal(t, "candidate crash 1", candidates[0].Title)
}
