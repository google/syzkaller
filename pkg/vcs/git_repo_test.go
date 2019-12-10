// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func init() {
	// Disable sandboxing entirely because we create test repos without sandboxing.
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
}

func TestGitRepo(t *testing.T) {
	t.Parallel()
	baseDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)
	repo1 := CreateTestRepo(t, baseDir, "repo1")
	repo2 := CreateTestRepo(t, baseDir, "repo2")
	repo := newGit(filepath.Join(baseDir, "repo"), nil)
	{
		com, err := repo.Poll(repo1.Dir, "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo1.Commits["master"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		com, err := repo.CheckoutBranch(repo1.Dir, "branch1")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo1.Commits["branch1"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo1.Commits["branch1"]["0"]
		com, err := repo.CheckoutCommit(repo1.Dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		commits, err := repo.ListRecentCommits(repo1.Commits["branch1"]["1"].Hash)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"repo1-branch1-1", "repo1-branch1-0", "repo1-master-0"}
		if diff := cmp.Diff(commits, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.Commits["branch1"]["0"]
		com, err := repo.CheckoutCommit(repo2.Dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.Commits["branch1"]["1"]
		com, err := repo.CheckoutCommit(repo2.Dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		com, err := repo.CheckoutBranch(repo2.Dir, "branch2")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo2.Commits["branch2"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.Commits["branch2"]["0"]
		com, err := repo.SwitchCommit(want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	repoDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(repoDir)
	repo := MakeTestRepo(t, repoDir)
	prevHash := ""
	for i, test := range metadataTests {
		repo.CommitChange(test.description)
		com, err := repo.repo.HeadCommit()
		if err != nil {
			t.Fatal(err)
		}
		checkCommit(t, i, test, com, false)
		if len(com.Parents) != 1 || com.Parents[0] != prevHash {
			t.Fatalf("bad parents: %+q, expect %q", com.Parents, prevHash)
		}
		prevHash = com.Hash
	}
	commits, err := repo.repo.ExtractFixTagsFromCommits("HEAD", extractFixTagsEmail)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadataTests) != len(commits) {
		t.Fatalf("want %v commits, got %v", len(metadataTests), len(commits))
	}
	for i, test := range metadataTests {
		checkCommit(t, i, test, commits[len(commits)-i-1], true)
		for _, title := range []string{test.title, test.title2} {
			if title == "" {
				continue
			}
			com, err := repo.repo.GetCommitByTitle(title)
			if err != nil {
				t.Error(err)
			} else if com == nil {
				t.Errorf("no commits found by title %q", title)
			} else if com.Title != title {
				t.Errorf("wrong commit %q found by title %q", com.Title, title)
			}
		}
	}
}

func checkCommit(t *testing.T, idx int, test testCommit, com *Commit, checkTags bool) {
	if !checkTags {
		return
	}
	if test.title != com.Title {
		t.Errorf("#%v: want title %q, got %q", idx, test.title, com.Title)
	}
	if test.author != com.Author {
		t.Errorf("#%v: want author %q, got %q", idx, test.author, com.Author)
	}
	if userName != com.AuthorName {
		t.Errorf("#%v: want author name %q, got %q", idx, userName, com.Author)
	}
	if diff := cmp.Diff(test.cc, com.CC); diff != "" {
		t.Logf("%#v", com.CC)
		t.Error(diff)
	}
	if diff := cmp.Diff(test.tags, com.Tags); checkTags && diff != "" {
		t.Error(diff)
	}
}

type testCommit struct {
	description string
	title       string
	title2      string
	author      string
	cc          []string
	tags        []string
}

// nolint: lll
var metadataTests = []testCommit{
	{
		description: `dashboard/app: bump max repros per bug to 10

Reported-by: syzbot+8e4090902540da8c6e8f@my.mail.com
`,
		title:  "dashboard/app: bump max repros per bug to 10",
		author: userEmail,
		cc:     []string{userEmail},
		tags:   []string{"8e4090902540da8c6e8f"},
	},
	{
		description: `executor: remove dead code

Reported-by: syzbot+8e4090902540da8c6e8f@my.mail.com
Reported-by: syzbot <syzbot+a640a0fc325c29c3efcb@my.mail.com>
`,
		title:  "executor: remove dead code",
		author: userEmail,
		cc:     []string{userEmail},
		tags:   []string{"8e4090902540da8c6e8f", "a640a0fc325c29c3efcb"},
	},
	{
		description: `pkg/csource: fix string escaping bug

Reported-and-tested-by: syzbot+8e4090902540da8c6e8fa640a0fc325c29c3efcb@my.mail.com
Tested-by: syzbot+4234987263748623784623758235@my.mail.com
`,
		title:  "pkg/csource: fix string escaping bug",
		author: userEmail,
		cc:     []string{"syzbot+4234987263748623784623758235@my.mail.com", "syzbot+8e4090902540da8c6e8fa640a0fc325c29c3efcb@my.mail.com", userEmail},
		tags:   []string{"8e4090902540da8c6e8fa640a0fc325c29c3efcb", "4234987263748623784623758235"},
	},
	{
		description: `When freeing a lockf struct that already is part of a linked list, make sure to update the next pointer for the preceding lock. Prevents a double free panic.

ok millert@
Reported-by: syzbot+6dd701dc797b23b8c761@my.mail.com
`,
		title:  "When freeing a lockf struct that already is part of a linked list, make sure to update the next pointer for the preceding lock. Prevents a double free panic.",
		author: userEmail,
		cc:     []string{userEmail},
		tags:   []string{"6dd701dc797b23b8c761"},
	},
	{
		description: `ipmr: properly check rhltable_init() return value

commit 8fb472c09b9d ("ipmr: improve hash scalability")
added a call to rhltable_init() without checking its return value.
 
This problem was then later copied to IPv6 and factorized in commit
0bbbf0e7d0e7 ("ipmr, ip6mr: Unite creation of new mr_table")
 
Fixes: 8fb472c09b9d ("ipmr: improve hash scalability")
Fixes: 0bbbf0e7d0e7 ("ipmr, ip6mr: Unite creation of new mr_table")
Reported-by: syzbot+6dd701dc797b23b8c761@my.mail.com
`,
		title:  "ipmr: properly check rhltable_init() return value",
		title2: "net-backports: ipmr: properly check rhltable_init() return value",
		author: userEmail,
		cc:     []string{userEmail},
		tags:   []string{"6dd701dc797b23b8c761"},
	},
	{
		description: `f2fs: sanity check for total valid node blocks

Reported-by: syzbot+bf9253040425feb155ad@my.mail.com
Reported-by: syzbot+bf9253040425feb155ad@my.mail.com
`,
		title:  "f2fs: sanity check for total valid node blocks",
		author: userEmail,
		cc:     []string{userEmail},
		tags:   []string{"bf9253040425feb155ad"},
	},
	{
		description: `USB: fix usbmon BUG trigger

Automated tests triggered this by opening usbmon and accessing the
mmap while simultaneously resizing the buffers. This bug was with
us since 2006, because typically applications only size the buffers
once and thus avoid racing. Reported by Kirill A. Shutemov.

Reported-by: <syzbot+f9831b881b3e849829fc@my.mail.com>
Signed-off-by: Pete Zaitcev <zaitcev@redhat.com>
Cc: stable <stable@vger.kernel.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
`,
		title:  "USB: fix usbmon BUG trigger",
		author: userEmail,
		cc:     []string{"gregkh@linuxfoundation.org", userEmail, "zaitcev@redhat.com"},
		tags:   []string{"f9831b881b3e849829fc"},
	},
	{
		description: `Do more sanity checks when accepting socket addresses in routing messages from user land. Reported-by: syzbot+638dbf7851da8e255af5@my.mail.com`,
		title:       "Do more sanity checks when accepting socket addresses in routing messages from user land. Reported-by: syzbot+638dbf7851da8e255af5@my.mail.com",
		author:      userEmail,
		cc:          []string{userEmail},
		tags:        []string{"638dbf7851da8e255af5"},
	},
}

func TestBisect(t *testing.T) {
	t.Parallel()
	repoDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(repoDir)
	repo := MakeTestRepo(t, repoDir)
	var commits []string
	for i := 0; i < 5; i++ {
		repo.CommitChange(fmt.Sprintf("commit %v", i))
		com, err := repo.repo.HeadCommit()
		if err != nil {
			t.Fatal(err)
		}
		commits = append(commits, com.Hash)
		t.Logf("%v %v", com.Hash, com.Title)
	}
	type Test struct {
		pred   func() (BisectResult, error)
		result []string
	}
	tests := []Test{
		{
			// All are bad.
			func() (BisectResult, error) {
				return BisectBad, nil
			},
			[]string{commits[1]},
		},
		{
			// All are good.
			func() (BisectResult, error) {
				return BisectGood, nil
			},
			[]string{commits[4]},
		},
		{
			// All are skipped.
			func() (BisectResult, error) {
				return BisectSkip, nil
			},
			[]string{commits[1], commits[2], commits[3], commits[4]},
		},
		{
			// Some are skipped.
			func() (BisectResult, error) {
				current, err := repo.repo.HeadCommit()
				if err != nil {
					t.Fatal(err)
				}
				switch current.Hash {
				case commits[1]:
					return BisectSkip, nil
				case commits[2]:
					return BisectSkip, nil
				case commits[3]:
					return BisectGood, nil
				default:
					return 0, fmt.Errorf("unknown commit %v", current.Hash)
				}
			},
			[]string{commits[4]},
		},
		{
			// Some are skipped.
			func() (BisectResult, error) {
				current, err := repo.repo.HeadCommit()
				if err != nil {
					t.Fatal(err)
				}
				switch current.Hash {
				case commits[1]:
					return BisectGood, nil
				case commits[2]:
					return BisectSkip, nil
				case commits[3]:
					return BisectBad, nil
				default:
					return 0, fmt.Errorf("unknown commit %v", current.Hash)
				}
			},
			[]string{commits[2], commits[3]},
		},
		{
			// Some are skipped.
			func() (BisectResult, error) {
				current, err := repo.repo.HeadCommit()
				if err != nil {
					t.Fatal(err)
				}
				switch current.Hash {
				case commits[1]:
					return BisectSkip, nil
				case commits[2]:
					return BisectSkip, nil
				case commits[3]:
					return BisectGood, nil
				default:
					return 0, fmt.Errorf("unknown commit %v", current.Hash)
				}
			},
			[]string{commits[4]},
		},
	}
	for i, test := range tests {
		t.Logf("TEST %v", i)
		result, err := repo.repo.Bisect(commits[4], commits[0], (*testWriter)(t), test.pred)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, com := range result {
			got = append(got, com.Hash)
		}
		sort.Strings(got) // git result order is non-deterministic (wat)
		sort.Strings(test.result)
		if diff := cmp.Diff(test.result, got); diff != "" {
			t.Logf("result: %+v", got)
			t.Fatal(diff)
		}
	}
}

type testWriter testing.T

func (t *testWriter) Write(data []byte) (int, error) {
	(*testing.T)(t).Log(string(data))
	return len(data), nil
}
