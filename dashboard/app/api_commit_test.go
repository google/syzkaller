// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	db "google.golang.org/appengine/v2/datastore"
)

func TestCommitPersistence(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash := testCrash(build, 1)
	c.client.ReportCrash(crash)
	rep := c.globalClient.pollBug()

	// Specify fixing commit for the bug.
	reply, err := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix1"},
	})
	c.expectOK(err)
	c.expectEQ(reply.OK, true)

	// Poll to clear NeedCommitInfo and get the list of commits.
	poll, err := c.client.CommitPoll()
	c.expectOK(err)
	c.expectEQ(len(poll.Commits), 1)
	c.expectEQ(poll.Commits[0], "foo: fix1")

	// Upload commit info with various attributes.
	authorName := "Aidan Black"
	authorEmail := "aidan@black.com"
	commitDate := time.Date(2026, 2, 24, 12, 0, 0, 0, time.UTC)
	c.expectOK(c.client.UploadCommits([]dashapi.Commit{
		{
			Hash:       "hash1",
			Title:      "foo: fix1",
			Author:     authorEmail,
			AuthorName: authorName,
			Date:       commitDate,
		},
	}))

	// Verify that all attributes are persisted in the Datastore.
	var bugs []*Bug
	_, err = db.NewQuery("Bug").
		Filter("Namespace=", "test1").
		Filter("Commits=", "foo: fix1").
		GetAll(c.ctx, &bugs)
	c.expectOK(err)
	c.expectEQ(len(bugs), 1)
	bug := bugs[0]
	c.expectEQ(len(bug.CommitInfo), 1)
	c.expectEQ(bug.CommitInfo[0].Hash, "hash1")
	c.expectEQ(bug.CommitInfo[0].Author, authorEmail)
	c.expectEQ(bug.CommitInfo[0].AuthorName, authorName)
	c.expectEQ(bug.CommitInfo[0].Date, commitDate)
}
