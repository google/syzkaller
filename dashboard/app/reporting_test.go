// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestReportBug(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := &dashapi.Crash{
		BuildID:     "build1",
		Title:       "title1",
		Maintainers: []string{`"Foo Bar" <foo@bar.com>`, `bar@foo.com`},
		Log:         []byte("log1"),
		Report:      []byte("report1"),
	}
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	// Must get no reports for "unknown" type.
	pr := &dashapi.PollBugsRequest{
		Type: "unknown",
	}
	resp := new(dashapi.PollBugsResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Must get a proper report for "test" type.
	pr.Type = "test"
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep := resp.Reports[0]
	if rep.ID == "" {
		t.Fatalf("empty report ID")
	}
	_, dbCrash, dbBuild := c.loadBug(rep.ID)
	want := &dashapi.BugReport{
		Namespace:         "test1",
		Config:            []byte(`{"Index":1}`),
		ID:                rep.ID,
		First:             true,
		Title:             "title1",
		Maintainers:       []string{"bar@foo.com", "foo@bar.com"},
		CompilerID:        "compiler1",
		KernelRepo:        "repo1",
		KernelRepoAlias:   "repo1/branch1",
		KernelBranch:      "branch1",
		KernelCommit:      "1111111111111111111111111111111111111111",
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  buildCommitDate,
		KernelConfig:      []byte("config1"),
		KernelConfigLink:  externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig),
		Log:               []byte("log1"),
		LogLink:           externalLink(c.ctx, textCrashLog, dbCrash.Log),
		Report:            []byte("report1"),
		ReportLink:        externalLink(c.ctx, textCrashReport, dbCrash.Report),
		CrashID:           rep.CrashID,
		NumCrashes:        1,
		HappenedOn:        []string{"repo1/branch1"},
	}
	c.expectEQ(rep, want)

	// Since we did not update bug status yet, should get the same report again.
	reports := reportAllBugs(c, 1)
	c.expectEQ(reports[0], want)

	// Now add syz repro and check that we get another bug report.
	crash1.ReproOpts = []byte("some opts")
	crash1.ReproSyz = []byte("getpid()")
	want.First = false
	want.ReproSyz = []byte(syzReproPrefix + "#some opts\ngetpid()")
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
	if want.CrashID == reports[0].CrashID {
		t.Fatal("get the same CrashID for new crash")
	}
	_, dbCrash, _ = c.loadBug(rep.ID)
	want.CrashID = reports[0].CrashID
	want.NumCrashes = 2
	want.ReproSyzLink = externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	want.LogLink = externalLink(c.ctx, textCrashLog, dbCrash.Log)
	want.ReportLink = externalLink(c.ctx, textCrashReport, dbCrash.Report)
	c.expectEQ(reports[0], want)

	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelSyz,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// After bug update should not get the report again.
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Now close the bug in the first reporting.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusUpstream,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Check that bug updates for the first reporting fail now.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusOpen,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, false)

	// Report another crash with syz repro for this bug,
	// ensure that we still report the original crash in the next reporting.
	// That's what we've upstreammed, it's bad to switch crashes without reason.
	crash1.Report = []byte("report2")
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	// Check that we get the report in the second reporting.
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep2 := resp.Reports[0]
	if rep2.ID == "" || rep2.ID == rep.ID {
		t.Fatalf("bad report ID: %q", rep2.ID)
	}
	want.ID = rep2.ID
	want.First = true
	want.Config = []byte(`{"Index":2}`)
	want.NumCrashes = 3
	c.expectEQ(rep2, want)

	// Check that that we can't upstream the bug in the final reporting.
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusUpstream,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, false)
}

func TestInvalidBug(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	crash1.ReproC = []byte("int main() {}")
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	pr := &dashapi.PollBugsRequest{
		Type: "test",
	}
	resp := new(dashapi.PollBugsResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep := resp.Reports[0]
	c.expectEQ(rep.Title, "title1")

	cmd := &dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelC,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	{
		req := &dashapi.PollClosedRequest{
			IDs: []string{rep.ID, "foobar"},
		}
		resp := new(dashapi.PollClosedResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_closed", req, resp))
		c.expectEQ(len(resp.IDs), 0)
	}

	// Mark the bug as invalid.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusInvalid,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	{
		req := &dashapi.PollClosedRequest{
			IDs: []string{rep.ID, "foobar"},
		}
		resp := new(dashapi.PollClosedResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_closed", req, resp))
		c.expectEQ(len(resp.IDs), 1)
		c.expectEQ(resp.IDs[0], rep.ID)
	}

	// Now it should not be reported in either reporting.
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Now a similar crash happens again.
	crash2 := &dashapi.Crash{
		BuildID: "build1",
		Title:   "title1",
		Log:     []byte("log2"),
		Report:  []byte("report2"),
		ReproC:  []byte("int main() { return 1; }"),
	}
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	// Now it should be reported again.
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep = resp.Reports[0]
	if rep.ID == "" {
		t.Fatalf("empty report ID")
	}
	_, dbCrash, dbBuild := c.loadBug(rep.ID)
	want := &dashapi.BugReport{
		Namespace:         "test1",
		Config:            []byte(`{"Index":1}`),
		ID:                rep.ID,
		First:             true,
		Title:             "title1 (2)",
		CompilerID:        "compiler1",
		KernelRepo:        "repo1",
		KernelRepoAlias:   "repo1/branch1",
		KernelBranch:      "branch1",
		KernelCommit:      "1111111111111111111111111111111111111111",
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  buildCommitDate,
		KernelConfig:      []byte("config1"),
		KernelConfigLink:  externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig),
		Log:               []byte("log2"),
		LogLink:           externalLink(c.ctx, textCrashLog, dbCrash.Log),
		Report:            []byte("report2"),
		ReportLink:        externalLink(c.ctx, textCrashReport, dbCrash.Report),
		ReproC:            []byte("int main() { return 1; }"),
		ReproCLink:        externalLink(c.ctx, textReproC, dbCrash.ReproC),
		CrashID:           rep.CrashID,
		NumCrashes:        1,
		HappenedOn:        []string{"repo1/branch1"},
	}
	c.expectEQ(rep, want)

	cid := &dashapi.CrashID{
		BuildID: build.ID,
		Title:   crash1.Title,
	}
	c.expectOK(c.API(client1, key1, "report_failed_repro", cid, nil))
}

func TestReportingQuota(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	const numReports = 8 // quota is 3 per day
	for i := 0; i < numReports; i++ {
		crash := &dashapi.Crash{
			BuildID: "build1",
			Title:   fmt.Sprintf("title%v", i),
			Log:     []byte(fmt.Sprintf("log%v", i)),
			Report:  []byte(fmt.Sprintf("report%v", i)),
		}
		c.expectOK(c.API(client1, key1, "report_crash", crash, nil))
	}

	for _, reports := range []int{3, 3, 2, 0, 0} {
		c.advanceTime(24 * time.Hour)
		pr := &dashapi.PollBugsRequest{
			Type: "test",
		}
		resp := new(dashapi.PollBugsResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
		c.expectEQ(len(resp.Reports), reports)
		for _, rep := range resp.Reports {
			cmd := &dashapi.BugUpdate{
				ID:     rep.ID,
				Status: dashapi.BugStatusOpen,
			}
			reply := new(dashapi.BugUpdateReply)
			c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
			c.expectEQ(reply.OK, true)
		}
		// Out of quota for today, so must get 0 reports.
		c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
		c.expectEQ(len(resp.Reports), 0)
	}
}

// Basic dup scenario: mark one bug as dup of another.
func TestReportingDup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	crash2 := testCrash(build, 2)
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	pr := &dashapi.PollBugsRequest{
		Type: "test",
	}
	resp := new(dashapi.PollBugsResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 2)

	rep1 := resp.Reports[0]
	cmd := &dashapi.BugUpdate{
		ID:     rep1.ID,
		Status: dashapi.BugStatusOpen,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	rep2 := resp.Reports[1]
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusOpen,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Dup.
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusDup,
		DupOf:  rep1.ID,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	{
		// Both must be reported as open.
		req := &dashapi.PollClosedRequest{
			IDs: []string{rep1.ID, rep2.ID},
		}
		resp := new(dashapi.PollClosedResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_closed", req, resp))
		c.expectEQ(len(resp.IDs), 0)
	}

	// Undup.
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusOpen,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Dup again.
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusDup,
		DupOf:  rep1.ID,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Dup crash happens again, new bug must not be created.
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Now close the original bug, and check that new bugs for dup are now created.
	cmd = &dashapi.BugUpdate{
		ID:     rep1.ID,
		Status: dashapi.BugStatusInvalid,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	{
		// Now both must be reported as closed.
		req := &dashapi.PollClosedRequest{
			IDs: []string{rep1.ID, rep2.ID},
		}
		resp := new(dashapi.PollClosedResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_closed", req, resp))
		c.expectEQ(len(resp.IDs), 2)
		c.expectEQ(resp.IDs[0], rep1.ID)
		c.expectEQ(resp.IDs[1], rep2.ID)
	}

	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))
	c.expectOK(c.API(client1, key1, "reporting_poll_bugs", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	c.expectEQ(resp.Reports[0].Title, crash2.Title+" (2)")

	// Unduping after the canonical bugs was closed must not work
	// (we already created new bug for this report).
	cmd = &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusOpen,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, false)
}

// Dup bug onto a closed bug.
// A new crash report must create a new bug.
func TestReportingDupToClosed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	crash2 := testCrash(build, 2)
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	reports := reportAllBugs(c, 2)

	cmd := &dashapi.BugUpdate{
		ID:     reports[0].ID,
		Status: dashapi.BugStatusInvalid,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	cmd = &dashapi.BugUpdate{
		ID:     reports[1].ID,
		Status: dashapi.BugStatusDup,
		DupOf:  reports[0].ID,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))
	reports2 := reportAllBugs(c, 1)
	c.expectEQ(reports2[0].Title, crash2.Title+" (2)")
}

// Test that marking dups across reporting levels is not permitted.
func TestReportingDupCrossReporting(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	crash2 := testCrash(build, 2)
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	reports := reportAllBugs(c, 2)
	rep1 := reports[0]
	rep2 := reports[1]

	// Upstream second bug.
	cmd := &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusUpstream,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	reports = reportAllBugs(c, 1)
	rep3 := reports[0]

	{
		req := &dashapi.PollClosedRequest{
			IDs: []string{rep1.ID, rep2.ID, rep3.ID},
		}
		resp := new(dashapi.PollClosedResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll_closed", req, resp))
		c.expectEQ(len(resp.IDs), 1)
		c.expectEQ(resp.IDs[0], rep2.ID)
	}

	// Duping must fail all ways.
	cmds := []*dashapi.BugUpdate{
		&dashapi.BugUpdate{ID: rep1.ID, DupOf: rep1.ID},
		&dashapi.BugUpdate{ID: rep1.ID, DupOf: rep2.ID},
		&dashapi.BugUpdate{ID: rep1.ID, DupOf: rep3.ID},
		&dashapi.BugUpdate{ID: rep2.ID, DupOf: rep1.ID},
		&dashapi.BugUpdate{ID: rep2.ID, DupOf: rep2.ID},
		&dashapi.BugUpdate{ID: rep2.ID, DupOf: rep3.ID},
		&dashapi.BugUpdate{ID: rep3.ID, DupOf: rep1.ID},
		&dashapi.BugUpdate{ID: rep3.ID, DupOf: rep2.ID},
		&dashapi.BugUpdate{ID: rep3.ID, DupOf: rep3.ID},
	}
	for _, cmd := range cmds {
		t.Logf("duping %v -> %v", cmd.ID, cmd.DupOf)
		cmd.Status = dashapi.BugStatusDup
		c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
		c.expectEQ(reply.OK, false)
	}
}

func TestReportingFilter(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	crash1.Title = "skip without repro 1"
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	// This does not skip first reporting, because it does not have repro.
	rep1 := reportAllBugs(c, 1)[0]
	c.expectEQ(string(rep1.Config), `{"Index":1}`)

	crash1.ReproSyz = []byte("getpid()")
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	// This has repro but was already reported to first reporting,
	// so repro must go to the first reporting as well.
	rep2 := reportAllBugs(c, 1)[0]
	c.expectEQ(string(rep2.Config), `{"Index":1}`)

	// Now upstream it and it must go to the second reporting.
	cmd := &dashapi.BugUpdate{
		ID:     rep1.ID,
		Status: dashapi.BugStatusUpstream,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	rep3 := reportAllBugs(c, 1)[0]
	c.expectEQ(string(rep3.Config), `{"Index":2}`)

	// Now report a bug that must go to the second reporting right away.
	crash2 := testCrash(build, 2)
	crash2.Title = "skip without repro 2"
	crash2.ReproSyz = []byte("getpid()")
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	rep4 := reportAllBugs(c, 1)[0]
	c.expectEQ(string(rep4.Config), `{"Index":2}`)
}
