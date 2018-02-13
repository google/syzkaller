// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

// Basic scenario of marking a bug as fixed by a particular commit,
// discovering this commit on builder and marking the bug as ultimately fixed.
func TestFixBasic(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	builderPollReq := &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, true)

	reports := reportAllBugs(c, 1)
	rep := reports[0]

	// Specify fixing commit for the bug.
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Don't need repro once there are fixing commits.
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)

	// Check that the commit is now passed to builders.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Patches must not be reset on other actions.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusOpen,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Upstream commands must fail if patches are already present.
	// Right course of action is unclear in this situation,
	// so this test merely documents the current behavior.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusUpstream,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, false)

	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Upload another build with the commit present.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"foo: fix the crash"}
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Check that the commit is now not passed to this builder.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug (the old one must be marked as fixed).
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
	c.expectEQ(reports[0].Title, "title1 (2)")

	// Regression test: previously upstreamming failed because the new bug had fixing commits.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	cmd = &dashapi.BugUpdate{
		ID:     reports[0].ID,
		Status: dashapi.BugStatusUpstream,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)
}

// Test bug that is fixed by 2 commits.
func TestFixedByTwoCommits(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	builderPollReq := &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	reports := reportAllBugs(c, 1)
	rep := reports[0]

	// Specify fixing commit for the bug.
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"bar: prepare for fixing", "\"foo: fix the crash\""},
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Check that the commit is now passed to builders.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "bar: prepare for fixing")
	c.expectEQ(builderPollResp.PendingCommits[1], "foo: fix the crash")

	// Upload another build with only one of the commits.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"bar: prepare for fixing"}
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Check that it has not fixed the bug.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "bar: prepare for fixing")
	c.expectEQ(builderPollResp.PendingCommits[1], "foo: fix the crash")

	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Now upload build with both commits.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash", "bar: prepare for fixing"}
	c.expectOK(c.API(client1, key1, "upload_build", build3, nil))

	// Check that the commit is now not passed to this builder.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug (the old one must be marked as fixed).
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
	c.expectEQ(reports[0].Title, "title1 (2)")
}

// A bug is marked as fixed by one commit and then remarked as fixed by another.
func TestReFixed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	builderPollReq := &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	reports := reportAllBugs(c, 1)
	rep := reports[0]

	// Specify fixing commit for the bug.
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"a wrong one"},
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	cmd = &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	// Upload another build with the wrong commit.
	build2 := testBuild(2)
	build2.Manager = build1.Manager
	build2.Commits = []string{"a wrong one"}
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Check that it has not fixed the bug.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Now upload build with the right commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"the right one"}
	c.expectOK(c.API(client1, key1, "upload_build", build3, nil))

	// Check that the commit is now not passed to this builder.
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)
}

// Fixing commit is present on one manager, but missing on another.
func TestFixTwoManagers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	builderPollReq := &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	reports := reportAllBugs(c, 1)
	rep := reports[0]

	// Specify fixing commit for the bug.
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Now the second manager appears.
	build2 := testBuild(2)
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Check that the commit is now passed to builders.
	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	builderPollReq = &dashapi.BuilderPollReq{build2.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Now first manager picks up the commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash"}
	c.expectOK(c.API(client1, key1, "upload_build", build3, nil))

	// Check that the commit is now not passed to this builder.
	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// But still passed to another.
	builderPollReq = &dashapi.BuilderPollReq{build2.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "foo: fix the crash")

	// Check that the bug is still open.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Now the second manager picks up the commit.
	build4 := testBuild(4)
	build4.Manager = build2.Manager
	build4.Commits = []string{"foo: fix the crash"}
	c.expectOK(c.API(client1, key1, "upload_build", build4, nil))

	// Now the bug must be fixed.
	builderPollReq = &dashapi.BuilderPollReq{build2.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
	c.expectEQ(reports[0].Title, "title1 (2)")
}

func TestReFixedTwoManagers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	builderPollReq := &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	reports := reportAllBugs(c, 1)
	rep := reports[0]

	// Specify fixing commit for the bug.
	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Now the second manager appears.
	build2 := testBuild(2)
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Now first manager picks up the commit.
	build3 := testBuild(3)
	build3.Manager = build1.Manager
	build3.Commits = []string{"foo: fix the crash"}
	c.expectOK(c.API(client1, key1, "upload_build", build3, nil))

	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Now we change the fixing commit.
	cmd = &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Now it must again appear on both managers.
	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	builderPollReq = &dashapi.BuilderPollReq{build2.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "the right one")

	// Now the second manager picks up the second commit.
	build4 := testBuild(4)
	build4.Manager = build2.Manager
	build4.Commits = []string{"the right one"}
	c.expectOK(c.API(client1, key1, "upload_build", build4, nil))

	// The bug must be still open.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Specify fixing commit again, but it's the same one as before, so nothing changed.
	cmd = &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"the right one"},
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Now the first manager picks up the second commit.
	build5 := testBuild(5)
	build5.Manager = build1.Manager
	build5.Commits = []string{"the right one"}
	c.expectOK(c.API(client1, key1, "upload_build", build5, nil))

	// Now the bug must be fixed.
	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
	c.expectEQ(reports[0].Title, "title1 (2)")
}

// TestFixedWithCommitTags tests fixing of bugs with Reported-by commit tags.
func TestFixedWithCommitTags(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	build2 := testBuild(2)
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	crash1 := testCrash(build1, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	rep := reportAllBugs(c, 1)[0]

	// Upload build with 2 fixing commits for this bug.
	build1.FixCommits = []dashapi.FixCommit{{"fix commit 1", rep.ID}, {"fix commit 2", rep.ID}}
	c.expectOK(c.API(client1, key1, "upload_build", build1, nil))

	// Now the commits must be associated with the bug and the second
	// manager must get them as pending.
	builderPollReq := &dashapi.BuilderPollReq{build2.Manager}
	builderPollResp := new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 2)
	c.expectEQ(builderPollResp.PendingCommits[0], "fix commit 1")
	c.expectEQ(builderPollResp.PendingCommits[1], "fix commit 2")

	// The first manager must not get them.
	builderPollReq = &dashapi.BuilderPollReq{build1.Manager}
	builderPollResp = new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// The bug is still not fixed.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reportAllBugs(c, 0)

	// Now the second manager reports the same commits.
	// This must close the bug.
	build2.FixCommits = build1.FixCommits
	c.expectOK(c.API(client1, key1, "upload_build", build2, nil))

	// Commits must not be passed to managers.
	builderPollReq = &dashapi.BuilderPollReq{build2.Manager}
	builderPollResp = new(dashapi.BuilderPollResp)
	c.expectOK(c.API(client1, key1, "builder_poll", builderPollReq, builderPollResp))
	c.expectEQ(len(builderPollResp.PendingCommits), 0)

	// Ensure that a new crash creates a new bug.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	rep = reportAllBugs(c, 1)[0]
	c.expectEQ(rep.Title, "title1 (2)")
}
