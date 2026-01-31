// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitParseCommit(t *testing.T) {
	tests := map[string]*Commit{
		`2075b16e32c26e4031b9fd3cbe26c54676a8fcb5
rbtree: include rcu.h
foobar@foobar.de
Foo Bar
Fri May 11 16:02:14 2018 -0700
78eb0c6356cda285c6ee6e29bea0c0188368103e
Fri May 11 17:28:45 2018 -0700
Since commit c1adf20052d8 ("Introduce rb_replace_node_rcu()")
rbtree_augmented.h uses RCU related data structures but does not include
the header file.  It works as long as it gets somehow included before
that and fails otherwise.

Link: http://lkml.kernel.org/r/20180504103159.19938-1-bigeasy@linutronix.de
Signed-off-by: Foo Bad Baz <another@email.de>
Reviewed-by: <yetanother@email.org>
Cc: Unrelated Guy <somewhere@email.com>
Acked-by: Subsystem reviewer <Subsystem@reviewer.com>
Reported-and-tested-by: and@me.com
Reported-and-Tested-by: Name-name <name@name.com>
Tested-by: Must be correct <mustbe@correct.com>
Signed-off-by: Linux Master <linux@linux-foundation.org>
`: {
			Hash:       "2075b16e32c26e4031b9fd3cbe26c54676a8fcb5",
			Title:      "rbtree: include rcu.h",
			Author:     "foobar@foobar.de",
			AuthorName: "Foo Bar",
			Recipients: NewRecipients([]string{
				"and@me.com",
				"another@email.de",
				"foobar@foobar.de",
				"linux@linux-foundation.org",
				"mustbe@correct.com",
				"name@name.com",
				"subsystem@reviewer.com",
				"yetanother@email.org",
			}, To),
			Date:       time.Date(2018, 5, 11, 16, 02, 14, 0, time.FixedZone("", -7*60*60)),
			CommitDate: time.Date(2018, 5, 11, 17, 28, 45, 0, time.FixedZone("", -7*60*60)),
		},
	}
	for input, com := range tests {
		res, err := gitParseCommit([]byte(input), nil, nil, nil)
		if err != nil && com != nil {
			t.Fatalf("want %+v, got error: %v", com, err)
		}
		if err == nil && com == nil {
			t.Fatalf("want error, got commit %+v", res)
		}
		if com == nil {
			continue
		}
		if com.Hash != res.Hash {
			t.Fatalf("want hash %q, got %q", com.Hash, res.Hash)
		}
		if com.Title != res.Title {
			t.Fatalf("want title %q, got %q", com.Title, res.Title)
		}
		if com.Author != res.Author {
			t.Fatalf("want author %q, got %q", com.Author, res.Author)
		}
		if diff := cmp.Diff(com.Recipients, res.Recipients); diff != "" {
			t.Fatalf("bad CC: %v", diff)
		}
		if !com.Date.Equal(res.Date) {
			t.Fatalf("want date %v, got %v", com.Date, res.Date)
		}
		if !com.CommitDate.Equal(res.CommitDate) {
			t.Fatalf("want date %v, got %v", com.CommitDate, res.CommitDate)
		}
	}
}

func TestGitParseReleaseTags(t *testing.T) {
	input := `
v3.1
v2.6.12
v2.6.39
v3.0
v3.10
v2.6.13
v3.11
v3.19
v3.9
v3.2
v4.9-rc1
v4.9
v4.9-rc3
v4.9-rc2
v2.6.32
v4.0
vv4.1
v2.6-rc5
v4.1foo
voo
v1.foo
v2.6-rc2
v10.2.foo
v1.2.
v1.
`
	want := []string{
		"v4.9",
		"v4.0",
		"v3.19",
		"v3.11",
		"v3.10",
		"v3.9",
		"v3.2",
		"v3.1",
		"v3.0",
		"v2.6.39",
		"v2.6.32",
		"v2.6.13",
		"v2.6.12",
	}
	got := gitParseReleaseTags([]byte(input), false)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got bad tags\ngot:  %+v\nwant: %+v", got, want)
	}
	wantRC := []string{
		"v4.9",
		"v4.9-rc3",
		"v4.9-rc2",
		"v4.9-rc1",
		"v4.0",
		"v3.19",
		"v3.11",
		"v3.10",
		"v3.9",
		"v3.2",
		"v3.1",
		"v3.0",
		"v2.6.39",
		"v2.6.32",
		"v2.6.13",
		"v2.6.12",
		"v2.6-rc5",
		"v2.6-rc2",
	}
	gotRC := gitParseReleaseTags([]byte(input), true)
	if !reflect.DeepEqual(gotRC, wantRC) {
		t.Fatalf("got bad tags\ngot:  %+v\nwant: %+v", gotRC, wantRC)
	}
}

func TestGetCommitsByTitles(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	validateSuccess := func(commit *Commit, results []*Commit, missing []string, err error) {
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if len(missing) > 0 {
			t.Fatalf("expected 0 missing, got %v", missing)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 results, got %v", len(results))
		}
		if results[0].Hash != commit.Hash {
			t.Fatalf("found unexpected commit %v", results[0].Hash)
		}
	}

	// Put three commits in branch-a, two with the title we search for.
	// We expect GetCommitsByTitles to only return the most recent match.
	repo.Git("checkout", "-b", "branch-a")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "abc")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	commitA, _ := repo.repo.Commit(HEAD)
	results, missing, err := repo.repo.GetCommitsByTitles([]string{"target"})
	validateSuccess(commitA, results, missing, err)

	// Put another commit with the title we search for in another branch.
	// We expect GetCommitsByTitles to only find commits in the current branch.
	repo.Git("checkout", "-b", "branch-b")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	repo.Git("checkout", "branch-a")
	results, missing, err = repo.repo.GetCommitsByTitles([]string{"target"})
	validateSuccess(commitA, results, missing, err)

	// We expect GetCommitsByTitles to only find commits in the current branch.
	repo.Git("checkout", "branch-b")
	results, missing, err = repo.repo.GetCommitsByTitles([]string{"xyz"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(results) > 0 {
		t.Fatalf("expected 0 results, got %v", len(results))
	}
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing, got %v", missing)
	}
	if missing[0] != "xyz" {
		t.Fatalf("found unexpected value in missing %v", missing[0])
	}
}

func TestContains(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	// We expect Contains to return true, if commit is in current checkout.
	repo.Git("checkout", "-b", "branch-a")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	commitA, _ := repo.repo.Commit(HEAD)
	if contained, _ := repo.repo.Contains(commitA.Hash); !contained {
		t.Fatalf("contains claims commit that should be present is not")
	}
	if contained, _ := repo.repo.Contains("fake-hash"); contained {
		t.Fatalf("contains claims commit that is not present is present")
	}

	// Commits must only be searched for from the checkedout HEAD.
	repo.Git("checkout", "-b", "branch-b")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	commitB, _ := repo.repo.Commit(HEAD)
	repo.Git("checkout", "branch-a")
	if contained, _ := repo.repo.Contains(commitB.Hash); contained {
		t.Fatalf("contains found commit that is not in current branch")
	}
}

func TestLatestCommits(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	repo.Git("checkout", "-b", "branch-a")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	got, err := repo.repo.LatestCommits("", time.Time{})
	assert.NoError(t, err)
	assert.Len(t, got, 2, "expected 2 commits")
	for i, commit := range got {
		if contained, _ := repo.repo.Contains(commit.Hash); !contained {
			t.Fatalf("commit %d is not contained", i)
		}
	}

	// Now ignore the first commit.
	got2, err := repo.repo.LatestCommits(got[1].Hash, time.Time{})
	assert.NoError(t, err)
	assert.Len(t, got2, 1, "expected 1 commit")
	assert.Equal(t, got2[0].Hash, got[0].Hash, "expected to see the HEAD commit")

	// TODO: test the afterDate argument.
	// It will require setting the GIT_COMMITTER_DATE env variable.
}

func TestObject(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)
	firstRev := []byte("First revision")
	secondRev := []byte("Second revision")

	repo.CommitChangeset("first",
		FileContent{"object.txt", string(firstRev)})
	repo.CommitChangeset("second",
		FileContent{"object.txt", string(secondRev)})

	commits, err := repo.repo.LatestCommits("", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	// Verify file's contents at the first revision.
	data, err := repo.repo.Object("object.txt", commits[1].Hash)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(data, firstRev); diff != "" {
		t.Fatal(diff)
	}
	// And at the second one.
	data, err = repo.repo.Object("object.txt", commits[0].Hash)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(data, secondRev); diff != "" {
		t.Fatal(diff)
	}
	com, err := repo.repo.Commit(commits[0].Hash)
	if err != nil {
		t.Fatal(err.Error())
	}
	patch := []byte(`diff --git a/object.txt b/object.txt
index 103167d..fbf7a68 100644
--- a/object.txt
+++ b/object.txt
@@ -1 +1 @@
-First revision
\ No newline at end of file
+Second revision
\ No newline at end of file
`)
	if diff := cmp.Diff(com.Patch, patch); diff != "" {
		t.Fatal(diff)
	}
}

func TestMergeBase(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	// Create base branch.
	repo.Git("checkout", "-b", "base")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	baseCommit, _ := repo.repo.Commit(HEAD)

	// Fork off another branch.
	repo.Git("checkout", "-b", "fork")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	forkCommit, _ := repo.repo.Commit(HEAD)

	// Ensure that merge base points to the base commit.
	mergeCommits, err := repo.repo.MergeBases(baseCommit.Hash, forkCommit.Hash)
	if err != nil {
		t.Fatal(err)
	} else if len(mergeCommits) != 1 || mergeCommits[0].Hash != baseCommit.Hash {
		t.Fatalf("expected base commit, got %v", mergeCommits)
	}

	// Let branches diverge.
	repo.Git("checkout", "base")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "newBase")
	newBaseCommit, _ := repo.repo.Commit(HEAD)

	repo.Git("checkout", "fork")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "newFork")
	newForkCommit, _ := repo.repo.Commit(HEAD)

	// The merge base should remain the same.
	mergeCommits, err = repo.repo.MergeBases(newBaseCommit.Hash, newForkCommit.Hash)
	if err != nil {
		t.Fatal(err)
	} else if len(mergeCommits) != 1 || mergeCommits[0].Hash != baseCommit.Hash {
		t.Fatalf("expected base commit (%s), got %d other commits",
			baseCommit.Hash, len(mergeCommits))
	}

	// Now do the merge.
	repo.Git("merge", "base")

	// And advance the fork branch.
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	newNewForkCommit, _ := repo.repo.Commit(HEAD)

	// The merge base should point to the last commit in `base`.
	mergeCommits, err = repo.repo.MergeBases(newBaseCommit.Hash, newNewForkCommit.Hash)
	if err != nil {
		t.Fatal(err)
	} else if len(mergeCommits) != 1 || mergeCommits[0].Hash != newBaseCommit.Hash {
		t.Fatalf("expected base commit, got %v", mergeCommits)
	}
}

func TestGitCustomRefs(t *testing.T) {
	remoteRepoDir := t.TempDir()
	remote := MakeTestRepo(t, remoteRepoDir)
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "base commit")
	remote.Git("checkout", "-b", "base_branch")
	remote.Git("tag", "base_tag")

	// Create a commit non reachable from any branch or tag.
	remote.Git("checkout", "base_branch")
	remote.Git("checkout", "-b", "temp_branch")
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "detached commit")
	// Add a ref to prevent the commit from getting garbage collected.
	remote.Git("update-ref", "refs/custom/test", "temp_branch")
	refCommit, _ := remote.repo.Commit(HEAD)

	// Remove the branch, let the commit stay only in refs.
	remote.Git("checkout", "base_branch")
	remote.Git("branch", "-D", "temp_branch")

	// Create a local repo.
	localRepoDir := t.TempDir()
	local := newGitRepo(localRepoDir, nil, nil)

	// Fetch the commit from the custom ref.
	_, err := local.CheckoutCommit(remoteRepoDir, refCommit.Hash)
	assert.NoError(t, err)
}

func TestGitRemoteTags(t *testing.T) {
	remoteRepoDir := t.TempDir()
	remote := MakeTestRepo(t, remoteRepoDir)
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "base commit")
	remote.Git("checkout", "-b", "base_branch")
	remote.Git("tag", "v1.0")

	// Diverge sub_branch and add a tag.
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "sub-branch")
	remote.Git("checkout", "-b", "sub_branch")
	remote.Git("tag", "v2.0")

	// Create a local repo.
	localRepoDir := t.TempDir()
	local := newGitRepo(localRepoDir, nil, nil)

	// Ensure all tags were fetched.
	commit, err := local.CheckoutCommit(remoteRepoDir, "sub_branch")
	assert.NoError(t, err)
	tags, err := local.previousReleaseTags(commit.Hash, true, false, false)
	assert.NoError(t, err)
	sort.Strings(tags)
	assert.Equal(t, []string{"v1.0", "v2.0"}, tags)
}

func TestGitFetchShortHash(t *testing.T) {
	remoteRepoDir := t.TempDir()
	remote := MakeTestRepo(t, remoteRepoDir)
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "base commit")
	remote.Git("checkout", "-b", "base_branch")
	remote.Git("tag", "base_tag")
	remote.Git("checkout", "-b", "temp_branch")
	remote.Git("commit", "--no-edit", "--allow-empty", "-m", "detached commit")
	refCommit, _ := remote.repo.Commit(HEAD)

	// Create a local repo.
	localRepoDir := t.TempDir()
	local := newGitRepo(localRepoDir, nil, nil)

	// Fetch the commit from the custom ref.
	_, err := local.CheckoutCommit(remoteRepoDir, refCommit.Hash[:12])
	assert.NoError(t, err)
}

func TestParseGitDiff(t *testing.T) {
	list := ParseGitDiff([]byte(`diff --git a/a.txt b/a.txt
index 4c5fd91..8fe1e32 100644
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-First file
+First file!
diff --git a/b.txt b/b.txt
new file mode 100644
index 0000000..f8a9677
--- /dev/null
+++ b/b.txt
@@ -0,0 +1 @@
+Second file.
diff --git a/c.txt b/c.txt
deleted file mode 100644
index f70f10e..0000000
--- a/c.txt
+++ /dev/null
@@ -1 +0,0 @@
-A
`))
	assert.Equal(t, list, []ModifiedFile{
		{
			Name:     `a.txt`,
			LeftHash: `4c5fd91`,
		},
		{
			Name:     `b.txt`,
			LeftHash: `0000000`,
		},
		{
			Name:     `c.txt`,
			LeftHash: `f70f10e`,
		},
	})
}

func TestGitFileHashes(t *testing.T) {
	repo := MakeTestRepo(t, t.TempDir())
	commit1 := repo.CommitChangeset("first commit", FileContent{"object.txt", "some text"})
	commit2 := repo.CommitChangeset("second commit", FileContent{"object2.txt", "some text2"})

	map1, err := repo.repo.fileHashes(commit1.Hash, []string{"object.txt", "object2.txt"})
	require.NoError(t, err)
	assert.NotEmpty(t, map1["object.txt"])

	map2, err := repo.repo.fileHashes(commit2.Hash, []string{"object.txt", "object2.txt"})
	require.NoError(t, err)
	assert.NotEmpty(t, map2["object.txt"])
	assert.NotEmpty(t, map2["object2.txt"])
}

func TestBaseForDiff(t *testing.T) {
	repo := MakeTestRepo(t, t.TempDir())
	repo.CommitChangeset("first commit",
		FileContent{"a.txt", "content of a.txt"},
		FileContent{"b.txt", "content of b.txt"},
	)
	commit2 := repo.CommitChangeset("second commit",
		FileContent{"c.txt", "content of c.txt"},
		FileContent{"d.txt", "content of d.txt"},
	)
	// Create a diff.
	commit3 := repo.CommitChangeset("third commit",
		FileContent{"a.txt", "update a.txt"},
	)
	diff, err := repo.repo.Diff(commit2.Hash, commit3.Hash)
	require.NoError(t, err)
	t.Run("conflicting", func(t *testing.T) {
		_, err := repo.repo.SwitchCommit(commit2.Hash)
		require.NoError(t, err)
		// Create a different change on top of commit2.
		repo.Git("checkout", "-b", "branch-a")
		repo.CommitChangeset("patch a.txt",
			FileContent{"a.txt", "another change to a.txt"},
		)
		// Yet the patch could only be applied to commit1 or commit2.
		base, err := repo.repo.BaseForDiff(diff, &debugtracer.TestTracer{T: t})
		require.NoError(t, err)
		require.Len(t, base, 1)
		require.Len(t, base[0].Branches, 2)
		assert.Equal(t, "branch-a", base[0].Branches[0])
		// Different git versions name it differently.
		assert.True(t, base[0].Branches[1] == "master" || base[0].Branches[1] == "main",
			"branch=%q", base[0].Branches[1])
		assert.Equal(t, commit2.Hash, base[0].Hash)
	})
	t.Run("choose latest", func(t *testing.T) {
		_, err := repo.repo.SwitchCommit(commit2.Hash)
		require.NoError(t, err)
		// Wait a second before adding another commit.
		// Git does not remember milliseconds, so otherwise the commit sorting may be flaky.
		time.Sleep(time.Second)
		repo.Git("checkout", "-b", "branch-b")
		commit4 := repo.CommitChangeset("unrelated commit",
			FileContent{"new.txt", "create new file"},
		)
		// Since the commit did not touch a.txt, it's the expected one.
		base, err := repo.repo.BaseForDiff(diff, &debugtracer.TestTracer{T: t})
		require.NoError(t, err)
		require.Len(t, base, 2)
		assert.Equal(t, []string{"branch-b"}, base[0].Branches)
		assert.Equal(t, commit4.Hash, base[0].Hash)
		assert.Equal(t, commit2.Hash, base[1].Hash)
	})
	t.Run("unknown objects", func(t *testing.T) {
		// It's not okay if the diff contains unknown hashes.
		diff2 := `
diff --git a/b.txt b/b.txt
deleted file mode 100644
index f70f10e..0000000
--- a/b.txt
+++ /dev/null
@@ -1 +0,0 @@
-A`
		twoDiffs := append(append([]byte{}, diff...), diff2...)
		base, err := repo.repo.BaseForDiff(twoDiffs, &debugtracer.TestTracer{T: t})
		require.NoError(t, err)
		require.Nil(t, base)
	})
	t.Run("ignore new files", func(t *testing.T) {
		diff2 := `
diff --git a/a.txt b/a.txt
new file mode 100644
index 0000000..fa49b07
--- /dev/null
+++ b/a.txt
@@ -0,0 +1 @@
+new file
diff --git a/a.txt b/a.txt
index fa49b07..01c887f 100644
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-new file
+edit file
`
		twoDiffs := append(append([]byte{}, diff...), diff2...)
		base, err := repo.repo.BaseForDiff(twoDiffs, &debugtracer.TestTracer{T: t})
		require.NoError(t, err)
		require.Len(t, base, 2)
	})
	t.Run("empty patch", func(t *testing.T) {
		base, err := repo.repo.BaseForDiff([]byte{}, &debugtracer.TestTracer{T: t})
		require.NoError(t, err)
		require.Nil(t, base)
	})
}
