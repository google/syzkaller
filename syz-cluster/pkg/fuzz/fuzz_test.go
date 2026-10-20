// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	pkgbuild "github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nolint: dupl
func TestShouldSkipFuzzing(t *testing.T) {
	t.Run("one empty", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
			},
		))
	})
	t.Run("equal symbols", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
		))
	})
	t.Run("ignore known variables", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "raw_data": "A", "vermagic": "A"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "raw_data": "B", "vermagic": "B"},
			},
		))
	})
	t.Run("same len, different hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "different"},
			},
		))
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
				Data: map[string]string{"C": "1", "D": "different"},
			},
		))
	})
	t.Run("different len, same hashes", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1", "B": "2", "C": "new"},
			},
		))
	})
	t.Run("ignored variable only in one kernel", func(t *testing.T) {
		assert.True(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1", "vermagic": "A"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1"},
			},
		))
	})
	t.Run("new data symbol, same data len", func(t *testing.T) {
		// The ignored variable in base must not hide the new symbol in patched.
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1", "vermagic": "A"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1", "D": "new"},
			},
		))
	})
	t.Run("removed data symbol", func(t *testing.T) {
		assert.False(t, shouldSkipFuzzing(
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1", "D": "2"},
			},
			pkgbuild.SectionHashes{
				Text: map[string]string{"A": "1"},
				Data: map[string]string{"C": "1"},
			},
		))
	})
}

func TestBugTitleRe(t *testing.T) {
	re, err := compileTitleFilter(&api.FuzzConfig{})
	require.NoError(t, err)
	assert.True(t, re.MatchString("any title must match"))

	re, err = compileTitleFilter(&api.FuzzConfig{
		BugTitleRe: `^Prefix:`,
	})
	require.NoError(t, err)
	assert.True(t, re.MatchString("Prefix: must pass"))
	assert.False(t, re.MatchString("Without prefix"))
}

func TestPrepareCorpus(t *testing.T) {
	// The "common" record is present in both corpuses.
	first := makeCorpus(t, map[string]string{"key1": "prog1", "common": "prog"})
	second := makeCorpus(t, map[string]string{"key2": "prog2", "common": "prog"})
	local := makeCorpus(t, map[string]string{"key3": "prog3", "common": "prog"})
	localFile := filepath.Join(t.TempDir(), "local.db")
	require.NoError(t, os.WriteFile(localFile, local, 0600))

	mux := http.NewServeMux()
	mux.HandleFunc("/first", func(w http.ResponseWriter, r *http.Request) { w.Write(first) })
	mux.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) { w.Write(second) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	workdir := t.TempDir()
	require.NoError(t, prepareCorpus(context.Background(), workdir,
		[]string{server.URL + "/first", server.URL + "/second"}, []string{localFile}, nil))

	corpus, err := db.OpenReadOnly(filepath.Join(workdir, "corpus.db"))
	require.NoError(t, err)
	records := map[string]string{}
	for key, rec := range corpus.Records {
		records[key] = string(rec.Val)
	}
	assert.Equal(t, map[string]string{
		"key1":   "prog1",
		"key2":   "prog2",
		"key3":   "prog3",
		"common": "prog",
	}, records)

	// The downloaded files must not be left behind.
	entries, err := os.ReadDir(workdir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// makeCorpus returns the serialized corpus DB with the given records.
func makeCorpus(t *testing.T, records map[string]string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.db")
	corpus, err := db.Open(path, false)
	require.NoError(t, err)
	for key, val := range records {
		corpus.Save(key, []byte(val), 0)
	}
	require.NoError(t, corpus.Flush())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
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
			Title:   "corrupted report crash",
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report_corrupted", CorruptedReport: true},
		},
		{
			Title:   "ignored status crash",
			Status:  manager.DiffBugStatusIgnored,
			Patched: manager.DiffBugInfo{Crashes: 5, Report: "report3"},
		},
	}

	candidates := FilterFindingCandidates(bugs)
	require.Len(t, candidates, 1)
	assert.Equal(t, "candidate crash 1", candidates[0].Title)
}
