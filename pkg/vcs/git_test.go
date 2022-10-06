// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	commitA, _ := repo.repo.HeadCommit()
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
	commitA, _ := repo.repo.HeadCommit()
	if contained, _ := repo.repo.Contains(commitA.Hash); !contained {
		t.Fatalf("contains claims commit that should be present is not")
	}
	if contained, _ := repo.repo.Contains("fake-hash"); contained {
		t.Fatalf("contains claims commit that is not present is present")
	}

	// Commits must only be searched for from the checkedout HEAD.
	repo.Git("checkout", "-b", "branch-b")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "target")
	commitB, _ := repo.repo.HeadCommit()
	repo.Git("checkout", "branch-a")
	if contained, _ := repo.repo.Contains(commitB.Hash); contained {
		t.Fatalf("contains found commit that is not in current branch")
	}
}
