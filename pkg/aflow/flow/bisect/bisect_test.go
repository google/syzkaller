// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestValidateFinderOutputs(t *testing.T) {
	t.Parallel()
	repoDir := filepath.Join(t.TempDir(), "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	repo.Git("checkout", "-b", "main")
	c1 := repo.CommitChangeset("net: initial implementation", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 1;\n",
	})
	c2 := repo.CommitChangeset("net: add helper", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 2;\n",
	})

	repo.Git("checkout", "-b", "other", c1.Hash)
	otherCommit := repo.CommitChangeset("other: side branch commit", vcs.FileContent{
		File:    "other.c",
		Content: "int y = 1;\n",
	})

	repo.Git("checkout", "main")
	repo.Git("merge", "--no-ff", "other", "-m", "Merge branch 'other'")
	headCommit := repo.CommitChangeset("net: head commit", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 3;\n",
	})
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

	state := finderState{
		KernelSrc:    repoDir,
		KernelCommit: headCommit.Hash,
	}

	t.Run("empty commits", func(t *testing.T) {
		got, err := validateFinderOutputs(nil, state, finderOutputs{})
		require.NoError(t, err)
		require.Empty(t, got.CandidateCommits)
	})

	t.Run("valid short hash and deduplication", func(t *testing.T) {
		got, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{c1.Hash[:12], c2.Hash, c1.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{c1.Hash, c2.Hash}, got.CandidateCommits)
	})

	t.Run("too many commits", func(t *testing.T) {
		_, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{c1.Hash, c1.Hash, c1.Hash, c1.Hash, c1.Hash, c1.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("too many candidate commits (6); provide at most %d commits or an empty list", maxCandidateCommits))
	})

	t.Run("empty hash string", func(t *testing.T) {
		_, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{""},
		})
		require.EqualError(t, err, "commit hash must not be empty")
	})

	t.Run("non-existent hash", func(t *testing.T) {
		badHash := "0123456789abcdef0123456789abcdef01234567"
		_, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{badHash},
		})
		require.EqualError(t, err, fmt.Sprintf("commit hash %q not found in the repository", badHash))
	})

	t.Run("unreachable commit", func(t *testing.T) {
		_, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{unreachableCommit.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is not reachable from the current commit", unreachableCommit.Hash))
	})

	t.Run("merge commit accepted", func(t *testing.T) {
		got, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{actualMerge.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{actualMerge.Hash}, got.CandidateCommits)
	})

	t.Run("commit reachable via merge is accepted", func(t *testing.T) {
		got, err := validateFinderOutputs(nil, state, finderOutputs{
			CandidateCommits: []string{otherCommit.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{otherCommit.Hash}, got.CandidateCommits)
	})

	t.Run("fix bisection rejects crash commit and older commits", func(t *testing.T) {
		fixState := finderState{
			KernelSrc:    repoDir,
			KernelCommit: headCommit.Hash,
			CrashCommit:  c2.Hash,
		}
		for _, oldHash := range []string{c1.Hash, c2.Hash} {
			_, err := validateFinderOutputs(nil, fixState, finderOutputs{
				CandidateCommits: []string{oldHash},
			})
			require.EqualError(t, err,
				fmt.Sprintf("commit %q is already present in the crash commit %v; identify a commit after the crash commit",
					oldHash, c2.Hash))
		}
		// Commits introduced after c2 (including otherCommit merged after c2, and headCommit) are accepted.
		got, err := validateFinderOutputs(nil, fixState, finderOutputs{
			CandidateCommits: []string{headCommit.Hash, otherCommit.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{headCommit.Hash, otherCommit.Hash}, got.CandidateCommits)
	})
}

func TestFormatBisect(t *testing.T) {
	t.Parallel()
	repoDir := filepath.Join(t.TempDir(), "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	c1 := repo.CommitChangeset("net: fix refcount\n\nReviewed-by: Reviewer <rev@example.com>", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 1;\n",
	})

	aflow.TestAction(t, formatBisect, "", formatBisectArgs{
		KernelSrc:        repoDir,
		CandidateCommits: []string{c1.Hash},
	}, formatBisectResult{
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

	aflow.TestAction(t, formatBisect, "", formatBisectArgs{
		KernelSrc: repoDir,
	}, formatBisectResult{}, "")
}
