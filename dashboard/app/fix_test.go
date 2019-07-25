// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

// Basic scenario of marking a bug as fixed by a particular commit,
// discovering this commit on builder and marking the bug as ultimately fixed.
func TestFixBasic(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	builderPollResp, _ := c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, true)

	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	})
	c.expectEQ(reply.OK, true)

	// Don't need repro once there are fixing commits.
	needRepro, _ = c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)

	// Check that the commit is now passed to builders.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Patches must not be reset on other actions.
	c.client.updateBug(rep.ID, dashapi.BugStatusOpen, "")

	// Upstream commands must fail if patches are already present.
	// Right course of action is unclear in this situation,
	// so this test merely documents the current behavior.
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusUpstream,
	})
	c.expectEQ(reply.OK, false)

	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Upload another build with the commit present.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"foo: fix the crash"}
	c.client.UploadBuild(build2)

	// Check that the commit is now not passed to this builder.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug (the old one must be marked as fixed).
	c.client.ReportCrash(crash1)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, "title1 (2)")

	// Regression test: previously upstreamming failed because the new bug had fixing commits.
	c.client.ReportCrash(crash1)
	c.client.updateBug(rep2.ID, dashapi.BugStatusUpstream, "")
	c.client.pollBug()
}

// Test bug that is fixed by 2 commits.
func TestFixedByTwoCommits(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	builderPollResp, _ := c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"bar: prepare for fixing", "\"foo: fix the crash\""},
	})
	c.expectEQ(reply.OK, true)

	// Check that the commit is now passed to builders.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "bar: prepare for fixing")
	c.expectEQ(builderPollResp.PendingCommits[1], "foo: fix the crash")

	// Upload another build with only one of the commits.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"bar: prepare for fixing"}
	c.client.UploadBuild(build2)

	// Check that it has not fixed the bug.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "bar: prepare for fixing")
	c.expectEQ(builderPollResp.PendingCommits[1], "foo: fix the crash")

	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Now upload build with both commits.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash", "bar: prepare for fixing"}
	c.client.UploadBuild(build3)

	// Check that the commit is now not passed to this builder.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug (the old one must be marked as fixed).
	c.client.ReportCrash(crash1)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, "title1 (2)")
}

// A bug is marked as fixed by one commit and then remarked as fixed by another.
func TestReFixed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	builderPollResp, _ := c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	c.advanceTime(time.Hour)
	rep := c.client.pollBug()

	bug, _, _ := c.loadBug(rep.ID)
	c.expectEQ(bug.LastActivity, c.mockedTime)
	c.expectEQ(bug.FixTime, time.Time{})

	// Specify fixing commit for the bug.
	c.advanceTime(time.Hour)
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"a wrong one"},
	})
	c.expectEQ(reply.OK, true)

	bug, _, _ = c.loadBug(rep.ID)
	c.expectEQ(bug.LastActivity, c.mockedTime)
	c.expectEQ(bug.FixTime, c.mockedTime)

	c.advanceTime(time.Hour)
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	})
	c.expectEQ(reply.OK, true)

	bug, _, _ = c.loadBug(rep.ID)
	c.expectEQ(bug.LastActivity, c.mockedTime)
	c.expectEQ(bug.FixTime, c.mockedTime)

	// No updates, just check that LastActivity time is updated, FixTime preserved.
	fixTime := c.mockedTime
	c.advanceTime(time.Hour)
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusOpen,
	})
	c.expectEQ(reply.OK, true)
	bug, _, _ = c.loadBug(rep.ID)
	c.expectEQ(bug.LastActivity, c.mockedTime)
	c.expectEQ(bug.FixTime, fixTime)

	// Send the same fixing commit, check that LastActivity time is updated, FixTime preserved.
	c.advanceTime(time.Hour)
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	})
	c.expectEQ(reply.OK, true)
	bug, _, _ = c.loadBug(rep.ID)
	c.expectEQ(bug.LastActivity, c.mockedTime)
	c.expectEQ(bug.FixTime, fixTime)

	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	// Upload another build with the wrong commit.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"a wrong one"}
	c.client.UploadBuild(build2)

	// Check that it has not fixed the bug.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Now upload build with the right commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"the right one"}
	c.client.UploadBuild(build3)

	// Check that the commit is now not passed to this builder.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)
}

// Fixing commit is present on one manager, but missing on another.
func TestFixTwoManagers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	builderPollResp, _ := c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	})
	c.expectEQ(reply.OK, true)

	// Now the second manager appears.
	build2 := testBuild(2)
	c.client.UploadBuild(build2)

	// Check that the commit is now passed to builders.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	builderPollResp, _ = c.client.BuilderPoll(build2.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Now first manager picks up the commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash"}
	c.client.UploadBuild(build3)

	// Check that the commit is now not passed to this builder.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// But still passed to another.
	builderPollResp, _ = c.client.BuilderPoll(build2.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Check that the bug is still open.
	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Now the second manager picks up the commit.
	build4 := testBuild(4)
	build4.Manager = build2.Manager
	build4.Commits = []string{"foo: fix the crash"}
	c.client.UploadBuild(build4)

	// Now the bug must be fixed.
	builderPollResp, _ = c.client.BuilderPoll(build2.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	c.client.ReportCrash(crash1)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, "title1 (2)")
}

func TestReFixedTwoManagers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	builderPollResp, _ := c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	})
	c.expectEQ(reply.OK, true)

	// Now the second manager appears.
	build2 := testBuild(2)
	c.client.UploadBuild(build2)

	// Now first manager picks up the commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash"}
	c.client.UploadBuild(build3)

	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Now we change the fixing commit.
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	})
	c.expectEQ(reply.OK, true)

	// Now it must again appear on both managers.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	// Now the second manager picks up the second commit.
	build4 := testBuild(4)
	build4.Manager = build2.Manager
	build4.Commits = []string{"the right one"}
	c.client.UploadBuild(build4)

	// The bug must be still open.
	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Specify fixing commit again, but it's the same one as before, so nothing changed.
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	})
	c.expectEQ(reply.OK, true)

	// Now the first manager picks up the second commit.
	build5 := testBuild(5)
	build5.Manager = build1.Manager
	build5.Commits = []string{"the right one"}
	c.client.UploadBuild(build5)

	// Now the bug must be fixed.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	c.client.ReportCrash(crash1)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, "title1 (2)")
}

// TestFixedWithCommitTags tests fixing of bugs with Reported-by commit tags.
func TestFixedWithCommitTags(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	build2 := testBuild(2)
	c.client.UploadBuild(build2)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)

	rep := c.client.pollBug()

	// Upload build with 2 fixing commits for this bug.
	build1.FixCommits = []dashapi.Commit{
		{Title: "fix commit 1", BugIDs: []string{rep.ID}},
		{Title: "fix commit 2", BugIDs: []string{rep.ID}},
	}
	c.client.UploadBuild(build1)

	// Now the commits must be associated with the bug and the second
	// manager must get them as pending.
	builderPollResp, _ := c.client.BuilderPoll(build2.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "fix commit 1")
	c.expectEQ(builderPollResp.PendingCommits[1], "fix commit 2")

	// The first manager must not get them.
	builderPollResp, _ = c.client.BuilderPoll(build1.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// The bug is still not fixed.
	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)

	// Now the second manager reports the same commits.
	// This must close the bug.
	build2.FixCommits = build1.FixCommits
	c.client.UploadBuild(build2)

	// Commits must not be passed to managers.
	builderPollResp, _ = c.client.BuilderPoll(build2.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug.
	c.client.ReportCrash(crash1)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, "title1 (2)")
}

// TestFixedDup tests Reported-by commit tag that comes for a dup.
// In such case we need to associate it with the canonical bugs.
func TestFixedDup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()

	crash2 := testCrash(build, 2)
	c.client.ReportCrash(crash2)
	rep2 := c.client.pollBug()

	// rep2 is a dup of rep1.
	c.client.updateBug(rep2.ID, dashapi.BugStatusDup, rep1.ID)

	// Upload build that fixes rep2.
	build.FixCommits = []dashapi.Commit{
		{Title: "fix commit 1", BugIDs: []string{rep2.ID}},
	}
	c.client.UploadBuild(build)

	// This must fix rep1.
	c.client.ReportCrash(crash1)
	rep3 := c.client.pollBug()
	c.expectEQ(rep3.Title, rep1.Title+" (2)")
}

// TestFixedDup2 tests Reported-by commit tag that comes for a dup.
// Ensure that non-canonical bug gets fixing commit too.
func TestFixedDup2(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	build2 := testBuild(2)
	c.client.UploadBuild(build2)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()

	crash2 := testCrash(build1, 2)
	c.client.ReportCrash(crash2)
	rep2 := c.client.pollBug()

	// rep2 is a dup of rep1.
	c.client.updateBug(rep2.ID, dashapi.BugStatusDup, rep1.ID)

	// Upload build that fixes rep2.
	build1.FixCommits = []dashapi.Commit{
		{Title: "fix commit 1", BugIDs: []string{rep2.ID}},
	}
	c.client.UploadBuild(build1)

	// Now undup the bugs. They are still unfixed as only 1 manager uploaded the commit.
	c.client.updateBug(rep2.ID, dashapi.BugStatusOpen, "")

	// Now the second manager reports the same commits. This must close both bugs.
	build2.FixCommits = build1.FixCommits
	c.client.UploadBuild(build2)
	c.client.pollBugs(0)

	c.advanceTime(24 * time.Hour)
	c.client.ReportCrash(crash1)
	rep3 := c.client.pollBug()
	c.expectEQ(rep3.Title, rep1.Title+" (2)")

	c.client.ReportCrash(crash2)
	rep4 := c.client.pollBug()
	c.expectEQ(rep4.Title, rep2.Title+" (2)")
}

// TestFixedDup3 tests Reported-by commit tag that comes for both dup and canonical bug.
func TestFixedDup3(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	build2 := testBuild(2)
	c.client.UploadBuild(build2)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()

	crash2 := testCrash(build1, 2)
	c.client.ReportCrash(crash2)
	rep2 := c.client.pollBug()

	// rep2 is a dup of rep1.
	c.client.updateBug(rep2.ID, dashapi.BugStatusDup, rep1.ID)

	// Upload builds that fix rep1 and rep2 with different commits.
	// This must fix rep1 eventually and we must not livelock in such scenario.
	build1.FixCommits = []dashapi.Commit{
		{Title: "fix commit 1", BugIDs: []string{rep1.ID}},
		{Title: "fix commit 2", BugIDs: []string{rep2.ID}},
	}
	build2.FixCommits = build1.FixCommits
	c.client.UploadBuild(build1)
	c.client.UploadBuild(build2)
	c.client.UploadBuild(build1)
	c.client.UploadBuild(build2)

	c.client.ReportCrash(crash1)
	rep3 := c.client.pollBug()
	c.expectEQ(rep3.Title, rep1.Title+" (2)")
}
