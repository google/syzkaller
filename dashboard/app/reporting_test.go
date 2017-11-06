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
	pr := &dashapi.PollRequest{
		Type: "unknown",
	}
	resp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Must get a proper report for "test" type.
	pr.Type = "test"
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep := resp.Reports[0]
	if rep.ID == "" {
		t.Fatalf("empty report ID")
	}
	want := &dashapi.BugReport{
		Namespace:    "test1",
		Config:       []byte(`{"Index":1}`),
		ID:           rep.ID,
		First:        true,
		Title:        "title1",
		Maintainers:  []string{"bar@foo.com", "foo@bar.com"},
		CompilerID:   "compiler1",
		KernelRepo:   "repo1",
		KernelBranch: "branch1",
		KernelCommit: "kernel_commit1",
		KernelConfig: []byte("config1"),
		Log:          []byte("log1"),
		Report:       []byte("report1"),
	}
	c.expectEQ(rep, want)

	// Since we did not update bug status yet, should get the same report again.
	reports := reportAllBugs(c, 1)
	c.expectEQ(reports[0], want)

	// Now add syz repro and check that we get another bug report.
	crash1.ReproOpts = []byte("some opts")
	crash1.ReproSyz = []byte("getpid()")
	want.First = false
	want.ReproSyz = []byte("#some opts\ngetpid()")
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))
	reports = reportAllBugs(c, 1)
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
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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

	// Check that we get the report in the second reporting.
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep2 := resp.Reports[0]
	if rep2.ID == "" || rep2.ID == rep.ID {
		t.Fatalf("bad report ID: %q", rep2.ID)
	}
	want.ID = rep2.ID
	want.First = true
	want.Config = []byte(`{"Index":2}`)
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

	pr := &dashapi.PollRequest{
		Type: "test",
	}
	resp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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

	// Mark the bug as invalid.
	cmd = &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusInvalid,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	// Now it should not be reported in either reporting.
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 1)
	rep = resp.Reports[0]
	if rep.ID == "" {
		t.Fatalf("empty report ID")
	}
	want := &dashapi.BugReport{
		Namespace:    "test1",
		Config:       []byte(`{"Index":1}`),
		ID:           rep.ID,
		First:        true,
		Title:        "title1 (2)",
		CompilerID:   "compiler1",
		KernelRepo:   "repo1",
		KernelBranch: "branch1",
		KernelCommit: "kernel_commit1",
		KernelConfig: []byte("config1"),
		Log:          []byte("log2"),
		Report:       []byte("report2"),
		ReproC:       []byte("int main() { return 1; }"),
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
		pr := &dashapi.PollRequest{
			Type: "test",
		}
		resp := new(dashapi.PollResponse)
		c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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
		c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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

	pr := &dashapi.PollRequest{
		Type: "test",
	}
	resp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 0)

	// Now close the original bug, and check that new bugs for dup are now created.
	cmd = &dashapi.BugUpdate{
		ID:     rep1.ID,
		Status: dashapi.BugStatusInvalid,
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
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
