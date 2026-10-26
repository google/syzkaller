// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

type testRepo struct {
	dir         string
	c1, c2      *vcs.Commit
	other       *vcs.Commit
	merge       *vcs.Commit
	head        *vcs.Commit
	unreachable *vcs.Commit
}

// makeBisectTestRepo creates a test repo with main checked out at head.
func makeBisectTestRepo(t *testing.T) *testRepo {
	// The history is:
	//     c1 -- c2 -- merge -- head      (main)
	//       \         /
	//        other ---                   (other)
	//       \
	//        unreachable                 (unreachable)
	repoDir := filepath.Join(osutil.SandboxTempDir(t), "linux")
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
	other := repo.CommitChangeset("other: side branch commit", vcs.FileContent{
		File:    "other.c",
		Content: "int y = 1;\n",
	})

	repo.Git("checkout", "main")
	repo.Git("merge", "--no-ff", "other", "-m", "Merge branch 'other'")
	head := repo.CommitChangeset("net: head commit", vcs.FileContent{
		File:    "net.c",
		Content: "int x = 3;\n",
	})
	merge, err := vcs.SandboxedGit(repoDir).Commit(head.Hash + "^")
	require.NoError(t, err)
	require.Len(t, merge.Parents, 2)

	repo.Git("checkout", "-b", "unreachable", c1.Hash)
	unreachable := repo.CommitChangeset("unreachable change", vcs.FileContent{
		File:    "unreach.c",
		Content: "int z = 1;\n",
	})
	repo.Git("checkout", "main")
	return &testRepo{
		dir:         repoDir,
		c1:          c1,
		c2:          c2,
		other:       other,
		merge:       merge,
		head:        head,
		unreachable: unreachable,
	}
}

func TestValidateCauseFinderOutputs(t *testing.T) {
	t.Parallel()
	r := makeBisectTestRepo(t)
	state := causeFinderState{
		KernelSrc:    r.dir,
		KernelCommit: r.head.Hash,
	}
	validate := func(hashes ...string) ([]string, error) {
		got, err := validateCauseFinderOutputs(nil, state, causeFinderOutputs{CandidateCommits: hashes})
		return got.CandidateCommits, err
	}

	t.Run("empty commits", func(t *testing.T) {
		got, err := validate()
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("valid short hash and deduplication", func(t *testing.T) {
		got, err := validate(r.c1.Hash[:12], r.c2.Hash, r.c1.Hash)
		require.NoError(t, err)
		require.Equal(t, []string{r.c1.Hash, r.c2.Hash}, got)
	})

	t.Run("too many commits", func(t *testing.T) {
		_, err := validate(r.c1.Hash, r.c1.Hash, r.c1.Hash, r.c1.Hash, r.c1.Hash, r.c1.Hash)
		require.EqualError(t, err,
			fmt.Sprintf("too many candidate commits (6); provide at most %d commits or an empty list", maxCandidateCommits))
	})

	t.Run("empty hash string", func(t *testing.T) {
		_, err := validate("")
		require.EqualError(t, err, "commit hash must not be empty")
	})

	t.Run("non-existent hash", func(t *testing.T) {
		badHash := "0123456789abcdef0123456789abcdef01234567"
		_, err := validate(badHash)
		require.EqualError(t, err, fmt.Sprintf("commit hash %q not found in the repository", badHash))
	})

	t.Run("unreachable commit", func(t *testing.T) {
		_, err := validate(r.unreachable.Hash)
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is not reachable from the current commit", r.unreachable.Hash))
	})

	t.Run("merge commit accepted", func(t *testing.T) {
		got, err := validate(r.merge.Hash)
		require.NoError(t, err)
		require.Equal(t, []string{r.merge.Hash}, got)
	})

	t.Run("commit reachable via merge is accepted", func(t *testing.T) {
		got, err := validate(r.other.Hash)
		require.NoError(t, err)
		require.Equal(t, []string{r.other.Hash}, got)
	})
}

func TestValidateFixFinderOutputs(t *testing.T) {
	t.Parallel()
	r := makeBisectTestRepo(t)
	state := fixFinderState{
		KernelSrc:    r.dir,
		KernelCommit: r.head.Hash,
		CrashCommit:  r.c2.Hash,
	}

	t.Run("missing crash commit", func(t *testing.T) {
		_, err := validateFixFinderOutputs(nil, fixFinderState{KernelSrc: r.dir, KernelCommit: r.head.Hash},
			fixFinderOutputs{CandidateCommits: []string{r.c1.Hash}})
		require.EqualError(t, err, "CrashCommit must not be empty")
	})

	t.Run("bug still present", func(t *testing.T) {
		got, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{BugStillPresent: true})
		require.NoError(t, err)
		require.True(t, got.BugStillPresent)
		require.Empty(t, got.CandidateCommits)
	})

	t.Run("bug still present with commits", func(t *testing.T) {
		_, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{
			BugStillPresent:  true,
			CandidateCommits: []string{r.head.Hash},
		})
		require.EqualError(t, err, "CandidateCommits must be empty when BugStillPresent is set")
	})

	t.Run("not determined", func(t *testing.T) {
		got, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{})
		require.NoError(t, err)
		require.False(t, got.BugStillPresent)
		require.Empty(t, got.CandidateCommits)
	})

	t.Run("rejects crash commit and older commits", func(t *testing.T) {
		for _, oldHash := range []string{r.c1.Hash, r.c2.Hash} {
			_, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{
				CandidateCommits: []string{oldHash},
			})
			require.EqualError(t, err,
				fmt.Sprintf("commit %q is already present in the crash commit %v; identify a commit after the crash commit",
					oldHash, r.c2.Hash))
		}
	})

	t.Run("accepts commits after the crash commit", func(t *testing.T) {
		// The side branch commit is not in c2, it's merged after it, so it's a valid candidate.
		got, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{
			CandidateCommits: []string{r.head.Hash[:12], r.other.Hash},
		})
		require.NoError(t, err)
		require.Equal(t, []string{r.head.Hash, r.other.Hash}, got.CandidateCommits)
	})

	t.Run("unreachable commit", func(t *testing.T) {
		_, err := validateFixFinderOutputs(nil, state, fixFinderOutputs{
			CandidateCommits: []string{r.unreachable.Hash},
		})
		require.EqualError(t, err,
			fmt.Sprintf("commit %q is not reachable from the current commit", r.unreachable.Hash))
	})
}

func TestFormatBisect(t *testing.T) {
	t.Parallel()
	repoDir := filepath.Join(osutil.SandboxTempDir(t), "linux")
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
				Hash:        c1.Hash,
				Title:       "net: fix refcount",
				AuthorName:  c1.AuthorName,
				AuthorEmail: c1.Author,
				Date:        c1.Date,
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
