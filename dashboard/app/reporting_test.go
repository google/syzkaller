// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/sys/targets"
)

func TestReportBug(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := &dashapi.Crash{
		BuildID:     "build1",
		Title:       "title1",
		Maintainers: []string{`"Foo Bar" <foo@bar.com>`, `bar@foo.com`},
		Log:         []byte("log1"),
		Flags:       dashapi.CrashUnderStrace,
		Report:      []byte("report1"),
		MachineInfo: []byte("machine info 1"),
	}
	c.client.ReportCrash(crash1)

	// Must get no reports for "unknown" type.
	resp, _ := c.client.ReportingPollBugs("unknown")
	c.expectEQ(len(resp.Reports), 0)

	// Must get a proper report for "test" type.
	resp, _ = c.client.ReportingPollBugs("test")
	c.expectEQ(len(resp.Reports), 1)
	rep := resp.Reports[0]
	c.expectNE(rep.ID, "")
	_, dbCrash, dbBuild := c.loadBug(rep.ID)
	want := &dashapi.BugReport{
		Type:              dashapi.ReportNew,
		BugStatus:         dashapi.BugStatusOpen,
		Namespace:         "test1",
		Config:            []byte(`{"Index":1}`),
		ID:                rep.ID,
		OS:                targets.Linux,
		Arch:              targets.AMD64,
		VMArch:            targets.AMD64,
		First:             true,
		Moderation:        true,
		Title:             "title1",
		Link:              fmt.Sprintf("https://testapp.appspot.com/bug?extid=%v", rep.ID),
		CreditEmail:       fmt.Sprintf("syzbot+%v@testapp.appspotmail.com", rep.ID),
		Maintainers:       []string{"bar@foo.com", "foo@bar.com"},
		CompilerID:        "compiler1",
		BuildID:           "build1",
		BuildTime:         timeNow(c.ctx),
		KernelRepo:        "repo1",
		KernelRepoAlias:   "repo1 branch1",
		KernelBranch:      "branch1",
		KernelCommit:      "1111111111111111111111111111111111111111",
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  buildCommitDate,
		KernelConfig:      []byte("config1"),
		KernelConfigLink:  externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig),
		SyzkallerCommit:   "syzkaller_commit1",
		MachineInfo:       []byte("machine info 1"),
		MachineInfoLink:   externalLink(c.ctx, textMachineInfo, dbCrash.MachineInfo),
		Log:               []byte("log1"),
		LogLink:           externalLink(c.ctx, textCrashLog, dbCrash.Log),
		LogHasStrace:      true,
		Report:            []byte("report1"),
		ReportLink:        externalLink(c.ctx, textCrashReport, dbCrash.Report),
		ReproOpts:         []uint8{},
		CrashID:           rep.CrashID,
		CrashTime:         timeNow(c.ctx),
		NumCrashes:        1,
		HappenedOn:        []string{"repo1 branch1"},
		Assets:            []dashapi.Asset{},
		ReportElements:    &dashapi.ReportElements{},
	}
	c.expectEQ(want, rep)

	// Since we did not update bug status yet, should get the same report again.
	c.expectEQ(c.client.pollBug(), want)

	// Now add syz repro and check that we get another bug report.
	crash1.ReproOpts = []byte("some opts")
	crash1.ReproSyz = []byte("getpid()")
	want.Type = dashapi.ReportRepro
	want.First = false
	want.ReproSyz = []byte(syzReproPrefix + "#some opts\ngetpid()")
	want.ReproOpts = []byte("some opts")
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()
	c.expectNE(want.CrashID, rep1.CrashID)
	_, dbCrash, _ = c.loadBug(rep.ID)
	want.CrashID = rep1.CrashID
	want.NumCrashes = 2
	want.ReproSyzLink = externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	want.LogLink = externalLink(c.ctx, textCrashLog, dbCrash.Log)
	want.ReportLink = externalLink(c.ctx, textCrashReport, dbCrash.Report)
	c.expectEQ(want, rep1)

	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelSyz,
	})
	c.expectEQ(reply.OK, true)

	// After bug update should not get the report again.
	c.client.pollBugs(0)

	// Now close the bug in the first reporting.
	c.client.updateBug(rep.ID, dashapi.BugStatusUpstream, "")

	// Check that bug updates for the first reporting fail now.
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{ID: rep.ID, Status: dashapi.BugStatusOpen})
	c.expectEQ(reply.OK, false)

	// Report another crash with syz repro for this bug,
	// ensure that we report the new crash in the next reporting.
	crash1.Report = []byte("report2")
	c.client.ReportCrash(crash1)

	// Check that we get the report in the second reporting.
	rep2 := c.client.pollBug()
	c.expectNE(rep2.ID, "")
	c.expectNE(rep2.ID, rep.ID)
	want.Type = dashapi.ReportNew
	want.ID = rep2.ID
	want.Report = []byte("report2")
	want.LogLink = rep2.LogLink
	want.ReportLink = rep2.ReportLink
	want.CrashID = rep2.CrashID
	want.ReproSyzLink = rep2.ReproSyzLink
	want.ReproOpts = []byte("some opts")
	want.Link = fmt.Sprintf("https://testapp.appspot.com/bug?extid=%v", rep2.ID)
	want.CreditEmail = fmt.Sprintf("syzbot+%v@testapp.appspotmail.com", rep2.ID)
	want.First = true
	want.Moderation = false
	want.Config = []byte(`{"Index":2}`)
	want.NumCrashes = 3
	c.expectEQ(want, rep2)

	// Check that that we can't upstream the bug in the final reporting.
	reply, _ = c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusUpstream,
	})
	c.expectEQ(reply.OK, false)
}

func TestInvalidBug(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrashWithRepro(build, 1)
	c.client.ReportCrash(crash1)

	rep := c.client.pollBug()
	c.expectEQ(rep.Title, "title1")

	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelC,
	})
	c.expectEQ(reply.OK, true)

	{
		closed, _ := c.client.ReportingPollClosed([]string{rep.ID, "foobar"})
		c.expectEQ(len(closed), 0)
	}

	// Mark the bug as invalid.
	c.client.updateBug(rep.ID, dashapi.BugStatusInvalid, "")

	{
		closed, _ := c.client.ReportingPollClosed([]string{rep.ID, "foobar"})
		c.expectEQ(len(closed), 1)
		c.expectEQ(closed[0], rep.ID)
	}

	// Now it should not be reported in either reporting.
	c.client.pollBugs(0)

	// Now a similar crash happens again.
	crash2 := &dashapi.Crash{
		BuildID: "build1",
		Title:   "title1",
		Log:     []byte("log2"),
		Report:  []byte("report2"),
		ReproC:  []byte("int main() { return 1; }"),
	}
	c.client.ReportCrash(crash2)

	// Now it should be reported again.
	rep = c.client.pollBug()
	c.expectNE(rep.ID, "")
	_, dbCrash, dbBuild := c.loadBug(rep.ID)
	want := &dashapi.BugReport{
		Type:              dashapi.ReportNew,
		BugStatus:         dashapi.BugStatusOpen,
		Namespace:         "test1",
		Config:            []byte(`{"Index":1}`),
		ID:                rep.ID,
		OS:                targets.Linux,
		Arch:              targets.AMD64,
		VMArch:            targets.AMD64,
		First:             true,
		Moderation:        true,
		Title:             "title1 (2)",
		Link:              fmt.Sprintf("https://testapp.appspot.com/bug?extid=%v", rep.ID),
		CreditEmail:       fmt.Sprintf("syzbot+%v@testapp.appspotmail.com", rep.ID),
		BuildID:           "build1",
		BuildTime:         timeNow(c.ctx),
		CompilerID:        "compiler1",
		KernelRepo:        "repo1",
		KernelRepoAlias:   "repo1 branch1",
		KernelBranch:      "branch1",
		KernelCommit:      "1111111111111111111111111111111111111111",
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  buildCommitDate,
		KernelConfig:      []byte("config1"),
		KernelConfigLink:  externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig),
		SyzkallerCommit:   "syzkaller_commit1",
		Log:               []byte("log2"),
		LogLink:           externalLink(c.ctx, textCrashLog, dbCrash.Log),
		Report:            []byte("report2"),
		ReportLink:        externalLink(c.ctx, textCrashReport, dbCrash.Report),
		ReproC:            []byte("int main() { return 1; }"),
		ReproCLink:        externalLink(c.ctx, textReproC, dbCrash.ReproC),
		ReproOpts:         []uint8{},
		CrashID:           rep.CrashID,
		CrashTime:         timeNow(c.ctx),
		NumCrashes:        1,
		HappenedOn:        []string{"repo1 branch1"},
		Assets:            []dashapi.Asset{},
		ReportElements:    &dashapi.ReportElements{},
	}
	c.expectEQ(want, rep)
	c.client.ReportFailedRepro(testCrashID(crash1))
}

func TestReportingQuota(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	const numReports = 8 // quota is 3 per day
	for i := 0; i < numReports; i++ {
		c.client.ReportCrash(testCrash(build, i))
	}

	for _, reports := range []int{3, 3, 2, 0, 0} {
		c.advanceTime(24 * time.Hour)
		c.client.pollBugs(reports)
		// Out of quota for today, so must get 0 reports.
		c.client.pollBugs(0)
	}
}

// Basic dup scenario: mark one bug as dup of another.
func TestReportingDup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	c.client.ReportCrash(crash2)

	reports := c.client.pollBugs(2)
	rep1 := reports[0]
	rep2 := reports[1]

	// Dup.
	c.client.updateBug(rep2.ID, dashapi.BugStatusDup, rep1.ID)
	{
		// Both must be reported as open.
		closed, _ := c.client.ReportingPollClosed([]string{rep1.ID, rep2.ID})
		c.expectEQ(len(closed), 0)
	}

	// Undup.
	c.client.updateBug(rep2.ID, dashapi.BugStatusOpen, "")

	// Dup again.
	c.client.updateBug(rep2.ID, dashapi.BugStatusDup, rep1.ID)

	// Dup crash happens again, new bug must not be created.
	c.client.ReportCrash(crash2)
	c.client.pollBugs(0)

	// Now close the original bug, and check that new bugs for dup are now created.
	c.client.updateBug(rep1.ID, dashapi.BugStatusInvalid, "")
	{
		// Now both must be reported as closed.
		closed, _ := c.client.ReportingPollClosed([]string{rep1.ID, rep2.ID})
		c.expectEQ(len(closed), 2)
		c.expectEQ(closed[0], rep1.ID)
		c.expectEQ(closed[1], rep2.ID)
	}

	c.client.ReportCrash(crash2)
	rep3 := c.client.pollBug()
	c.expectEQ(rep3.Title, crash2.Title+" (2)")

	// Unduping after the canonical bugs was closed must not work
	// (we already created new bug for this report).
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusOpen,
	})
	c.expectEQ(reply.OK, false)
}

// Dup bug onto a closed bug.
// A new crash report must create a new bug.
func TestReportingDupToClosed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	c.client.ReportCrash(crash2)

	reports := c.client.pollBugs(2)
	c.client.updateBug(reports[0].ID, dashapi.BugStatusInvalid, "")
	c.client.updateBug(reports[1].ID, dashapi.BugStatusDup, reports[0].ID)

	c.client.ReportCrash(crash2)
	rep2 := c.client.pollBug()
	c.expectEQ(rep2.Title, crash2.Title+" (2)")
}

// Test that marking dups across reporting levels is not permitted.
func TestReportingDupCrossReporting(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	c.client.ReportCrash(crash2)

	reports := c.client.pollBugs(2)
	rep1 := reports[0]
	rep2 := reports[1]

	// Upstream second bug.
	c.client.updateBug(rep2.ID, dashapi.BugStatusUpstream, "")
	rep3 := c.client.pollBug()

	{
		closed, _ := c.client.ReportingPollClosed([]string{rep1.ID, rep2.ID, rep3.ID})
		c.expectEQ(len(closed), 1)
		c.expectEQ(closed[0], rep2.ID)
	}

	// Duping must fail all ways.
	cmds := []*dashapi.BugUpdate{
		{ID: rep1.ID, DupOf: rep1.ID},
		{ID: rep1.ID, DupOf: rep2.ID},
		{ID: rep2.ID, DupOf: rep1.ID},
		{ID: rep2.ID, DupOf: rep2.ID},
		{ID: rep2.ID, DupOf: rep3.ID},
		{ID: rep3.ID, DupOf: rep1.ID},
		{ID: rep3.ID, DupOf: rep2.ID},
		{ID: rep3.ID, DupOf: rep3.ID},
	}
	for _, cmd := range cmds {
		t.Logf("duping %v -> %v", cmd.ID, cmd.DupOf)
		cmd.Status = dashapi.BugStatusDup
		reply, _ := c.client.ReportingUpdate(cmd)
		c.expectEQ(reply.OK, false)
	}
	// Special case of cross-reporting duping:
	cmd := &dashapi.BugUpdate{
		Status: dashapi.BugStatusDup,
		ID:     rep1.ID,
		DupOf:  rep3.ID,
	}
	t.Logf("duping %v -> %v", cmd.ID, cmd.DupOf)
	reply, _ := c.client.ReportingUpdate(cmd)
	c.expectTrue(reply.OK)
}

// Test that dups can't form a cycle.
// The test builds cycles of length 1..4.
func TestReportingDupCycle(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	const N = 4
	reps := make([]*dashapi.BugReport, N)
	for i := 0; i < N; i++ {
		t.Logf("*************** %v ***************", i)
		c.client.ReportCrash(testCrash(build, i))
		reps[i] = c.client.pollBug()
		replyError := "Can't dup bug to itself."
		if i != 0 {
			replyError = "Setting this dup would lead to a bug cycle, cycles are not allowed."
			reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
				Status: dashapi.BugStatusDup,
				ID:     reps[i-1].ID,
				DupOf:  reps[i].ID,
			})
			c.expectEQ(reply.OK, true)
		}
		reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
			Status: dashapi.BugStatusDup,
			ID:     reps[i].ID,
			DupOf:  reps[0].ID,
		})
		c.expectEQ(reply.OK, false)
		c.expectEQ(reply.Error, false)
		c.expectEQ(reply.Text, replyError)
		c.advanceTime(24 * time.Hour)
	}
}

func TestReportingFilter(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "skip with repro 1"
	c.client.ReportCrash(crash1)

	// This does not skip first reporting, because it does not have repro.
	rep1 := c.client.pollBug()
	c.expectEQ(string(rep1.Config), `{"Index":1}`)

	crash1.ReproSyz = []byte("getpid()")
	c.client.ReportCrash(crash1)

	// This has repro but was already reported to first reporting,
	// so repro must go to the first reporting as well.
	rep2 := c.client.pollBug()
	c.expectEQ(string(rep2.Config), `{"Index":1}`)

	// Now upstream it and it must go to the second reporting.
	c.client.updateBug(rep1.ID, dashapi.BugStatusUpstream, "")

	rep3 := c.client.pollBug()
	c.expectEQ(string(rep3.Config), `{"Index":2}`)

	// Now report a bug that must go to the second reporting right away.
	crash2 := testCrash(build, 2)
	crash2.Title = "skip with repro 2"
	crash2.ReproSyz = []byte("getpid()")
	c.client.ReportCrash(crash2)

	rep4 := c.client.pollBug()
	c.expectEQ(string(rep4.Config), `{"Index":2}`)
}

func TestMachineInfo(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	machineInfo := []byte("info1")

	// Create a crash with machine information and check the returned machine
	// information field is equal.
	crash := &dashapi.Crash{
		BuildID:     "build1",
		Title:       "title1",
		Maintainers: []string{`"Foo Bar" <foo@bar.com>`, `bar@foo.com`},
		Log:         []byte("log1"),
		Report:      []byte("report1"),
		MachineInfo: machineInfo,
	}
	c.client.ReportCrash(crash)
	rep := c.client.pollBug()
	c.expectEQ(machineInfo, rep.MachineInfo)

	// Check that a link to machine information page is created on the dashboard,
	// and the content is correct.
	indexPage, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	bugLinkRegex := regexp.MustCompile(`<a href="(/bug\?id=[^"]+)">title1</a>`)
	bugLinkSubmatch := bugLinkRegex.FindSubmatch(indexPage)
	c.expectEQ(len(bugLinkSubmatch), 2)
	bugURL := html.UnescapeString(string(bugLinkSubmatch[1]))

	bugPage, err := c.AuthGET(AccessAdmin, bugURL)
	c.expectOK(err)
	infoLinkRegex := regexp.MustCompile(`<a href="(/text\?tag=MachineInfo[^"]+)">info</a>`)
	infoLinkSubmatch := infoLinkRegex.FindSubmatch(bugPage)
	c.expectEQ(len(infoLinkSubmatch), 2)
	infoURL := html.UnescapeString(string(infoLinkSubmatch[1]))

	receivedInfo, err := c.AuthGET(AccessAdmin, infoURL)
	c.expectOK(err)
	c.expectEQ(receivedInfo, machineInfo)
}

func TestAltTitles1(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// crash2.AltTitles matches crash1.Title.
	crash1 := testCrash(build, 1)
	crash2 := testCrashWithRepro(build, 2)
	crash2.AltTitles = []string{crash1.Title}

	c.client.ReportCrash(crash1)
	rep := c.client.pollBug()
	c.expectEQ(rep.Title, crash1.Title)
	c.expectEQ(rep.Log, crash1.Log)

	c.client.ReportCrash(crash2)
	rep = c.client.pollBug()
	c.expectEQ(rep.Title, crash1.Title)
	c.expectEQ(rep.Log, crash2.Log)
}

func TestAltTitles2(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// crash2.Title matches crash1.AltTitles, but reported in opposite order.
	crash1 := testCrash(build, 1)
	crash2 := testCrash(build, 2)
	crash2.AltTitles = []string{crash1.Title}

	c.client.ReportCrash(crash2)
	rep := c.client.pollBug()
	c.expectEQ(rep.Title, crash2.Title)
	c.expectEQ(rep.Log, crash2.Log)

	c.client.ReportCrash(crash1)
	c.client.pollBugs(0)
}

func TestAltTitles3(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// crash2.AltTitles matches crash1.AltTitles.
	crash1 := testCrash(build, 1)
	crash1.AltTitles = []string{"foobar"}
	crash2 := testCrash(build, 2)
	crash2.AltTitles = crash1.AltTitles

	c.client.ReportCrash(crash1)
	c.client.pollBugs(1)
	c.client.ReportCrash(crash2)
	c.client.pollBugs(0)
}

func TestAltTitles4(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// crash1.AltTitles matches crash2.AltTitles which matches crash3.AltTitles.
	crash1 := testCrash(build, 1)
	crash1.AltTitles = []string{"foobar1"}
	crash2 := testCrash(build, 2)
	crash2.AltTitles = []string{"foobar1", "foobar2"}
	crash3 := testCrash(build, 3)
	crash3.AltTitles = []string{"foobar2"}

	c.client.ReportCrash(crash1)
	c.client.pollBugs(1)
	c.client.ReportCrash(crash2)
	c.client.pollBugs(0)
	c.client.ReportCrash(crash3)
	c.client.pollBugs(0)
}

func TestAltTitles5(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// Test which of the possible existing bugs we choose for merging.
	crash1 := testCrash(build, 1)
	crash1.AltTitles = []string{"foo"}
	c.client.ReportCrash(crash1)
	c.client.pollBugs(1)

	crash2 := testCrash(build, 2)
	crash2.Title = "bar"
	c.client.ReportCrash(crash2)
	c.client.pollBugs(1)

	crash3 := testCrash(build, 3)
	c.client.ReportCrash(crash3)
	c.client.pollBugs(1)
	crash3.AltTitles = []string{"bar"}
	c.client.ReportCrash(crash3)
	c.client.pollBugs(0)

	crash := testCrashWithRepro(build, 10)
	crash.Title = "foo"
	crash.AltTitles = []string{"bar"}
	c.client.ReportCrash(crash)
	rep := c.client.pollBug()
	c.expectEQ(rep.Title, crash2.Title)
	c.expectEQ(rep.Log, crash.Log)
}

func TestAltTitles6(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// Test which of the possible existing bugs we choose for merging in presence of closed bugs.
	crash1 := testCrash(build, 1)
	crash1.AltTitles = []string{"foo"}
	c.client.ReportCrash(crash1)
	rep := c.client.pollBug()
	c.client.updateBug(rep.ID, dashapi.BugStatusInvalid, "")
	c.client.ReportCrash(crash1)
	c.client.pollBug()

	crash2 := testCrash(build, 2)
	crash2.Title = "bar"
	c.client.ReportCrash(crash2)
	rep = c.client.pollBug()
	c.client.updateBug(rep.ID, dashapi.BugStatusInvalid, "")

	c.advanceTime(24 * time.Hour)
	crash3 := testCrash(build, 3)
	c.client.ReportCrash(crash3)
	c.client.pollBugs(1)
	crash3.AltTitles = []string{"foo"}
	c.client.ReportCrash(crash3)
	c.client.pollBugs(0)

	crash := testCrashWithRepro(build, 10)
	crash.Title = "foo"
	crash.AltTitles = []string{"bar"}
	c.client.ReportCrash(crash)
	rep = c.client.pollBug()
	c.expectEQ(rep.Title, crash1.Title+" (2)")
	c.expectEQ(rep.Log, crash.Log)
}

func TestAltTitles7(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// Test that bug merging is stable: if we started merging into a bug, we continue merging into that bug
	// even if a better candidate appears.
	crash1 := testCrash(build, 1)
	crash1.AltTitles = []string{"foo"}
	c.client.ReportCrash(crash1)
	c.client.pollBug()

	// This will be merged into crash1.
	crash2 := testCrash(build, 2)
	crash2.AltTitles = []string{"foo"}
	c.client.ReportCrash(crash2)
	c.client.pollBugs(0)

	// Now report a better candidate.
	crash3 := testCrash(build, 3)
	crash3.Title = "aaa"
	c.client.ReportCrash(crash3)
	c.client.pollBug()
	crash3.AltTitles = []string{crash2.Title}
	c.client.ReportCrash(crash3)
	c.client.pollBugs(0)

	// Now report crash2 with a repro and ensure that it's still merged into crash1.
	crash2.ReproOpts = []byte("some opts")
	crash2.ReproSyz = []byte("getpid()")
	c.client.ReportCrash(crash2)
	rep := c.client.pollBug()
	c.expectEQ(rep.Title, crash1.Title)
	c.expectEQ(rep.Log, crash2.Log)
}

func TestDetachExternalTracker(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)

	// Get single report for "test" type.
	resp, _ := c.client.ReportingPollBugs("test")
	c.expectEQ(len(resp.Reports), 1)
	rep1 := resp.Reports[0]
	c.expectNE(rep1.ID, "")
	c.expectEQ(string(rep1.Config), `{"Index":1}`)

	// Signal detach_reporting for current bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep1.ID,
		Status:     dashapi.BugStatusUpstream,
		ReproLevel: dashapi.ReproLevelNone,
		Link:       "http://URI/1",
		CrashID:    rep1.CrashID,
	})
	c.expectEQ(reply.OK, true)

	// Now add syz repro to check it doesn't use first reporting.
	crash1.ReproOpts = []byte("some opts")
	crash1.ReproSyz = []byte("getpid()")
	c.client.ReportCrash(crash1)

	// Fetch bug and check reporting path (Config) is different.
	rep2 := c.client.pollBug()
	c.expectNE(rep2.ID, "")
	c.expectEQ(string(rep2.Config), `{"Index":2}`)

	closed, _ := c.client.ReportingPollClosed([]string{rep1.ID, rep2.ID})
	c.expectEQ(len(closed), 1)
	c.expectEQ(closed[0], rep1.ID)
}

func TestUpdateBugReporting(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()
	setIDs := func(bug *Bug, arr []BugReporting) {
		for i := range arr {
			arr[i].ID = bugReportingHash(bug.keyHash(), arr[i].Name)
		}
	}
	now := timeNow(c.ctx)
	// We test against the test2 namespace.
	cfg := config.Namespaces["test2"]
	tests := []struct {
		Before []BugReporting
		After  []BugReporting
		Error  bool
	}{
		// Initially empty object.
		{
			Before: []BugReporting{},
			After: []BugReporting{
				{
					Name: "reporting1",
				},
				{
					Name: "reporting2",
				},
				{
					Name: "reporting3",
				},
			},
		},
		// Prepending and appending new reporting objects, the bug is not reported yet.
		{
			Before: []BugReporting{
				{
					Name: "reporting2",
				},
			},
			After: []BugReporting{
				{
					Name: "reporting1",
				},
				{
					Name: "reporting2",
				},
				{
					Name: "reporting3",
				},
			},
		},
		// The order or reportings is changed.
		{
			Before: []BugReporting{
				{
					Name: "reporting2",
				},
				{
					Name: "reporting1",
				},
				{
					Name: "reporting3",
				},
			},
			After: []BugReporting{},
			Error: true,
		},
		// Prepending and appending new reporting objects, the bug is already reported.
		{
			Before: []BugReporting{
				{
					Name:     "reporting2",
					Reported: now,
					ExtID:    "abcd",
				},
			},
			After: []BugReporting{
				{
					Name:     "reporting1",
					Closed:   now,
					Reported: now,
					Dummy:    true,
				},
				{
					Name:     "reporting2",
					Reported: now,
					ExtID:    "abcd",
				},
				{
					Name: "reporting3",
				},
			},
		},
		// It must look like as if the new Reporting was immediate.
		{
			Before: []BugReporting{
				{
					Name:     "reporting1",
					Reported: now.Add(-24 * time.Hour),
					ExtID:    "abcd",
				},
				{
					Name:     "reporting3",
					Reported: now,
					ExtID:    "efgh",
				},
			},
			After: []BugReporting{
				{
					Name:     "reporting1",
					Reported: now.Add(-24 * time.Hour),
					ExtID:    "abcd",
				},
				{
					Name:     "reporting2",
					Reported: now.Add(-24 * time.Hour),
					Closed:   now.Add(-24 * time.Hour),
					Dummy:    true,
				},
				{
					Name:     "reporting3",
					Reported: now,
					ExtID:    "efgh",
				},
			},
		},
	}
	for _, test := range tests {
		bug := &Bug{
			Title:     "bug",
			Reporting: test.Before,
			Namespace: "test2",
		}
		setIDs(bug, bug.Reporting)
		setIDs(bug, test.After)
		hasError := bug.updateReportings(cfg, now) != nil
		if hasError != test.Error {
			t.Errorf("Before: %#v, Expected error: %v, Got error: %v", test.Before, test.Error, hasError)
		}
		if !test.Error && !reflect.DeepEqual(bug.Reporting, test.After) {
			t.Errorf("Before: %#v, Expected After: %#v, Got After: %#v", test.Before, test.After, bug.Reporting)
		}
	}
}

func TestFullBugInfo(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	const crashTitle = "WARNING: abcd"

	// Oldest crash: with strace.
	crashStrace := testCrashWithRepro(build, 1)
	crashStrace.Title = crashTitle
	crashStrace.Flags = dashapi.CrashUnderStrace
	crashStrace.Report = []byte("with strace")
	c.client.ReportCrash(crashStrace)
	rep := c.client.pollBug()

	// Newer: just with repro.
	c.advanceTime(24 * 7 * time.Hour)
	crashRepro := testCrashWithRepro(build, 1)
	crashRepro.Title = crashTitle
	crashRepro.Report = []byte("with repro")
	c.client.ReportCrash(crashRepro)

	// Ensure we have some bisect jobs done.
	pollResp := c.client.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:    jobID,
		Build: *testBuild(3),
		Log:   []byte("bisect log"),
		Commits: []dashapi.Commit{
			{
				Hash:   "111111111111111111111111",
				Title:  "kernel: break build",
				Author: "hacker@kernel.org",
				CC:     []string{"reviewer1@kernel.org"},
				Date:   time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	c.client.expectOK(c.client.JobDone(done))
	c.client.pollBug()

	// Yet newer: no repro.
	c.advanceTime(24 * 7 * time.Hour)
	crashNew := testCrash(build, 1)
	crashNew.Title = crashTitle
	c.client.ReportCrash(crashNew)

	// And yet newer.
	c.advanceTime(24 * time.Hour)
	crashNew2 := testCrash(build, 1)
	crashNew2.Title = crashTitle
	crashNew2.Report = []byte("newest")
	c.client.ReportCrash(crashNew2)

	// Also create a bug in another namespace.
	otherBuild := testBuild(2)
	c.client2.UploadBuild(otherBuild)

	otherCrash := testCrash(otherBuild, 1)
	otherCrash.Title = crashTitle
	c.client2.ReportCrash(otherCrash)
	otherPollMsg := c.client2.pollEmailBug()
	_, otherExtBugID, _ := email.RemoveAddrContext(otherPollMsg.Sender)

	// Query the full bug info.
	info, err := c.client.LoadFullBug(&dashapi.LoadFullBugReq{BugID: rep.ID})
	c.expectOK(err)
	if info.BisectCause == nil {
		t.Fatalf("info.BisectCause is empty")
	}
	if info.BisectCause.BisectCause == nil {
		t.Fatalf("info.BisectCause.BisectCause is empty")
	}
	c.expectEQ(info.SimilarBugs, []*dashapi.SimilarBugInfo{{
		Title:     crashTitle,
		Namespace: "test2",
		Status:    dashapi.BugStatusOpen,
		Link:      "https://testapp.appspot.com/bug?extid=" + otherExtBugID,
	}})

	// There must be 3 crashes.
	reportsOrder := [][]byte{[]byte("newest"), []byte("with repro"), []byte("with strace")}
	c.expectEQ(len(info.Crashes), len(reportsOrder))
	for i, report := range reportsOrder {
		c.expectEQ(info.Crashes[i].Report, report)
	}
}

func TestUpdateReportApi(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// Report a crash.
	c.client.ReportCrash(testCrashWithRepro(build, 1))
	c.client.pollBug()

	listResp, err := c.client.BugList()
	c.expectOK(err)
	c.expectEQ(len(listResp.List), 1)

	// Load the bug info.
	bugID := listResp.List[0]
	rep, err := c.client.LoadBug(bugID)
	c.expectOK(err)

	// Now update the crash.
	setGuiltyFiles := []string{"fs/a.c", "net/b.c"}
	err = c.client.UpdateReport(&dashapi.UpdateReportReq{
		BugID:       bugID,
		CrashID:     rep.CrashID,
		GuiltyFiles: &setGuiltyFiles,
	})
	c.expectOK(err)

	// And make sure it's been updated.
	ret, err := c.client.LoadBug(bugID)
	if err != nil {
		t.Fatal(err)
	}
	if ret.ReportElements == nil {
		t.Fatalf("ReportElements is nil")
	}
	if diff := cmp.Diff(ret.ReportElements.GuiltyFiles, setGuiltyFiles); diff != "" {
		t.Fatal(diff)
	}
}

func TestReportDecommissionedBugs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientTestDecomm, keyTestDecomm, true)
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	rep := client.pollBug()

	closed, _ := client.ReportingPollClosed([]string{rep.ID})
	c.expectEQ(len(closed), 0)

	// And now let's decommission the namespace.
	config.Namespaces[rep.Namespace].Decommissioned = true
	defer func() { config.Namespaces[rep.Namespace].Decommissioned = false }()

	closed, _ = client.ReportingPollClosed([]string{rep.ID})
	c.expectEQ(len(closed), 1)
	c.expectEQ(closed[0], rep.ID)
}
