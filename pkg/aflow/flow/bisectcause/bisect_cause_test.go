// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisectcause

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestValidateCauseFinderOutputs(t *testing.T) {
	t.Parallel()
	repoDir := filepath.Join(t.TempDir(), "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	repo.Git("checkout", "-b", "main")
	c1 := repo.CommitChangeset("net: initial implementation", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 1;\n",
	})
	repo.SetTag("v6.9")
	c2 := repo.CommitChangeset("net: add helper", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 2;\n",
	})
	releaseCommit := repo.CommitChangeset("Linux 6.10", vcs.FileContent{
		File:    "Makefile",
		Content: "VERSION = 6\nPATCHLEVEL = 10\n",
	})
	repo.SetTag("v6.10")

	repo.Git("checkout", "-b", "other", c1.Hash)
	otherCommit := repo.CommitChangeset("other: side branch commit", vcs.FileContent{
		File:    "other.c",
		Content: "int y = 1;\n",
	})

	repo.Git("checkout", "main")
	repo.Git("merge", "--no-ff", "other", "-m", "Merge branch 'other'")
	mergeCommit := repo.CommitChangeset("net: head commit", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 3;\n",
	})
	// Get the actual merge commit (parent of mergeCommit).
	headCommit := mergeCommit
	git := vcs.Git{Dir: repoDir}
	actualMerge, err := git.Commit(headCommit.Hash + "^")
	require.NoError(t, err)
	require.Len(t, actualMerge.Parents, 2)

	// Create an unreachable commit on another branch.
	repo.Git("checkout", "-b", "unreachable", c1.Hash)
	unreachableCommit := repo.CommitChangeset("unreachable change", vcs.FileContent{
		File:    "unreach.c",
		Content: "int z = 1;\n",
	})
	repo.Git("checkout", "main")

	state := causeFinderState{
		KernelSrc:    repoDir,
		KernelCommit: headCommit.Hash,
	}

	t.Run("empty commits", func(t *testing.T) {
		got, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
		})
		require.NoError(t, err)
		require.Empty(t, got.CommitHashes)
	})

	t.Run("root cause provided skips summary and analysis check", func(t *testing.T) {
		stateWithRC := state
		stateWithRC.RootCause = "existing analysis"
		got, err := validateCauseFinderOutputs(nil, stateWithRC, causeFinderArgs{
			CommitHashes: []string{c1.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{c1.Hash}, got.CommitHashes)
	})

	t.Run("empty summary when no root cause provided", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  " ",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{c1.Hash},
		})
		require.EqualError(t, err, "RootCauseSummaryRaw must not be empty")
	})

	t.Run("empty analysis when no root cause provided", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: " ",
			CommitHashes:         []string{c1.Hash},
		})
		require.EqualError(t, err, "RootCauseAnalysisRaw must not be empty")
	})

	t.Run("valid short hash and deduplication", func(t *testing.T) {
		got, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{c1.Hash[:12], c2.Hash, c1.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{c1.Hash, c2.Hash}, got.CommitHashes)
	})

	t.Run("too many commits", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{c1.Hash, c1.Hash, c1.Hash, c1.Hash, c1.Hash, c1.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("too many candidate commits (6); provide at most %d commits or an empty list", maxCauseCommits))
	})

	t.Run("empty hash string", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{""},
		})
		require.EqualError(t, err, "commit hash must not be empty")
	})

	t.Run("non-existent hash", func(t *testing.T) {
		badHash := "0123456789abcdef0123456789abcdef01234567"
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{badHash},
		})
		require.EqualError(t, err, fmt.Sprintf("commit hash %q not found in the repository", badHash))
	})

	t.Run("unreachable commit", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{unreachableCommit.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is not reachable from the current commit", unreachableCommit.Hash))
	})

	t.Run("merge commit rejected", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{actualMerge.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is a merge commit; identify the non-merge commit that introduced the bug",
				actualMerge.Hash))
	})

	t.Run("release commit rejected", func(t *testing.T) {
		_, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{releaseCommit.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is a release commit; identify the actual commit that introduced the bug",
				releaseCommit.Hash))
	})

	t.Run("commit reachable via merge is accepted", func(t *testing.T) {
		got, err := validateCauseFinderOutputs(nil, state, causeFinderArgs{
			RootCauseSummaryRaw:  "s",
			RootCauseAnalysisRaw: "a",
			CommitHashes:         []string{otherCommit.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{otherCommit.Hash}, got.CommitHashes)
	})
}

func TestFormatBisectCause(t *testing.T) {
	t.Parallel()
	repoDir := filepath.Join(t.TempDir(), "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	c1 := repo.CommitChangeset("net: fix refcount\n\nReviewed-by: Reviewer <rev@example.com>", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 1;\n",
	})

	longExplanation := strings.Repeat("word ", 25)
	wrapped := strings.TrimSpace(strings.Repeat("word ", 16)) + "\n" +
		strings.TrimSpace(strings.Repeat("word ", 9))
	aflow.TestAction(t, formatBisectCause, "", formatBisectCauseArgs{
		KernelSrc:            repoDir,
		RootCauseSummaryRaw:  "short summary",
		RootCauseAnalysisRaw: longExplanation,
		BisectReasoningRaw:   "traced git blame to c1",
		CommitHashes:         []string{c1.Hash},
	}, formatBisectCauseResult{
		RootCauseSummary:  "short summary",
		RootCauseAnalysis: wrapped,
		BisectReasoning:   "traced git blame to c1",
		Commits: []ai.Commit{
			{
				Hash:       c1.Hash,
				Title:      "net: fix refcount",
				Author:     c1.Author,
				AuthorName: c1.AuthorName,
				Date:       c1.Date,
				Recipients: []ai.Recipient{
					{Email: "rev@example.com", To: true},
					{Email: c1.Author, To: true},
				},
			},
		},
	}, "")

	aflow.TestAction(t, formatBisectCause, "", formatBisectCauseArgs{
		KernelSrc:          repoDir,
		RootCause:          longExplanation,
		BisectReasoningRaw: "traced git blame to c1",
	}, formatBisectCauseResult{
		RootCauseAnalysis: wrapped,
		BisectReasoning:   "traced git blame to c1",
	}, "")
}
