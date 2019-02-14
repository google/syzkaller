// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"sort"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestCommitPoll(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()

	crash2 := testCrash(build1, 2)
	c.client.ReportCrash(crash2)
	rep2 := c.client.pollBug()

	// No commits in commit poll.
	commitPollResp, err := c.client.CommitPoll()
	c.expectOK(err)
	c.expectEQ(len(commitPollResp.Repos), 2)
	c.expectEQ(commitPollResp.Repos[0].URL, testConfig.Namespaces["test1"].Repos[0].URL)
	c.expectEQ(commitPollResp.Repos[0].Branch, testConfig.Namespaces["test1"].Repos[0].Branch)
	c.expectEQ(commitPollResp.Repos[1].URL, testConfig.Namespaces["test1"].Repos[1].URL)
	c.expectEQ(commitPollResp.Repos[1].Branch, testConfig.Namespaces["test1"].Repos[1].Branch)
	c.expectEQ(len(commitPollResp.Commits), 0)

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep1.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix1", "foo: fix2"},
	})
	c.expectEQ(reply.OK, true)

	// The commit should appear in commit poll.
	for i := 0; i < 2; i++ {
		commitPollResp, err = c.client.CommitPoll()
		c.expectOK(err)
		c.expectEQ(len(commitPollResp.Commits), 2)
		sort.Strings(commitPollResp.Commits)
		c.expectEQ(commitPollResp.Commits[0], "foo: fix1")
		c.expectEQ(commitPollResp.Commits[1], "foo: fix2")
	}

	// Upload hash for the first commit and fixing commit for the second bug.
	c.expectOK(c.client.UploadCommits([]dashapi.Commit{
		{Hash: "hash1", Title: "foo: fix1"},
		{Hash: "hash2", Title: "bar: fix3", BugIDs: []string{rep2.ID}},
		{Hash: "hash3", Title: "some unrelated commit", BugIDs: []string{"does not exist"}},
		{Hash: "hash4", Title: "another unrelated commit"},
	}))

	commitPollResp, err = c.client.CommitPoll()
	c.expectOK(err)
	c.expectEQ(len(commitPollResp.Commits), 2)
	sort.Strings(commitPollResp.Commits)
	c.expectEQ(commitPollResp.Commits[0], "foo: fix1")
	c.expectEQ(commitPollResp.Commits[1], "foo: fix2")

	// Upload hash for the second commit and a new fixing commit for the second bug.
	c.expectOK(c.client.UploadCommits([]dashapi.Commit{
		{Hash: "hash5", Title: "foo: fix2"},
		{Title: "bar: fix4", BugIDs: []string{rep2.ID}},
	}))

	commitPollResp, err = c.client.CommitPoll()
	c.expectOK(err)
	c.expectEQ(len(commitPollResp.Commits), 1)
	c.expectEQ(commitPollResp.Commits[0], "bar: fix4")

	// Upload hash for the second commit and a new fixing commit for the second bug.
	c.expectOK(c.client.UploadCommits([]dashapi.Commit{
		{Hash: "hash1", Title: "foo: fix1"},
		{Hash: "hash5", Title: "foo: fix2"},
		{Hash: "hash6", Title: "bar: fix4"},
	}))

	commitPollResp, err = c.client.CommitPoll()
	c.expectOK(err)
	c.expectEQ(len(commitPollResp.Commits), 0)
}
