// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestEmailNotifUpstreamEmbargo(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	c.client2.ReportCrash(crash)
	report := c.pollEmailBug()
	c.expectEQ(report.To, []string{"test@syzkaller.com"})

	// Upstreaming happens after 14 days, so no emails yet.
	c.advanceTime(13 * 24 * time.Hour)
	c.expectNoEmail()

	// Now we should get notification about upstreaming and upstream report:
	c.advanceTime(2 * 24 * time.Hour)
	notifUpstream := c.pollEmailBug()
	upstreamReport := c.pollEmailBug()
	c.expectEQ(notifUpstream.Sender, report.Sender)
	c.expectEQ(notifUpstream.Body, "Sending this report upstream.")
	c.expectNE(upstreamReport.Sender, report.Sender)
	c.expectEQ(upstreamReport.To, []string{"bugs@syzkaller.com", "default@maintainers.com"})
}

func TestEmailNotifUpstreamSkip(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Title = "skip with repro 1"
	c.client2.ReportCrash(crash)
	report := c.pollEmailBug()
	c.expectEQ(report.To, []string{"test@syzkaller.com"})

	// No emails yet.
	c.expectNoEmail()

	// Now upload repro and it should be auto-upstreamed.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("getpid()")
	c.client2.ReportCrash(crash)
	notifUpstream := c.pollEmailBug()
	upstreamReport := c.pollEmailBug()
	c.expectEQ(notifUpstream.Sender, report.Sender)
	c.expectEQ(notifUpstream.Body, "Sending this report upstream.")
	c.expectNE(upstreamReport.Sender, report.Sender)
	c.expectEQ(upstreamReport.To, []string{"bugs@syzkaller.com", "default@maintainers.com"})
}

func TestEmailNotifBadFix(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	c.client2.ReportCrash(crash)
	report := c.pollEmailBug()
	c.expectEQ(report.To, []string{"test@syzkaller.com"})

	c.incomingEmail(report.Sender, "#syz fix some: commit title")
	c.expectNoEmail()

	// Notification about bad fixing commit should be send after 90 days.
	c.advanceTime(50 * 24 * time.Hour)
	c.expectNoEmail()
	c.advanceTime(35 * 24 * time.Hour)
	c.expectNoEmail()
	c.advanceTime(10 * 24 * time.Hour)
	notif := c.pollEmailBug()
	if !strings.Contains(notif.Body, "This bug is marked as fixed by commit:\nsome: commit title\n") {
		t.Fatalf("bad notification text: %q", notif.Body)
	}
	// No notifications for another 14 days, then another one.
	c.advanceTime(13 * 24 * time.Hour)
	c.expectNoEmail()
	c.advanceTime(2 * 24 * time.Hour)
	notif = c.pollEmailBug()
	if !strings.Contains(notif.Body, "This bug is marked as fixed by commit:\nsome: commit title\n") {
		t.Fatalf("bad notification text: %q", notif.Body)
	}
}

func TestBugObsoleting(t *testing.T) {
	// To simplify test we specify all dates in days from a fixed point in time.
	const day = 24 * time.Hour
	days := func(n int) time.Time {
		t := time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC)
		t.Add(time.Duration(n+1) * day)
		return t
	}
	tests := []struct {
		bug    *Bug
		period time.Duration
	}{
		// Final bug with just 1 crash: max final period.
		{
			bug: &Bug{
				FirstTime:  days(0),
				LastTime:   days(0),
				NumCrashes: 1,
				Reporting:  []BugReporting{{Reported: days(0)}},
			},
			period: 100 * day,
		},
		// Non-final bug with just 1 crash: max non-final period.
		{
			bug: &Bug{
				FirstTime:  days(0),
				LastTime:   days(0),
				NumCrashes: 1,
				Reporting:  []BugReporting{{Reported: days(0)}, {}},
			},
			period: 60 * day,
		},
		// Special manger: max period that that manager.
		{
			bug: &Bug{
				FirstTime:  days(0),
				LastTime:   days(0),
				NumCrashes: 1,
				HappenedOn: []string{"special-obsoleting"},
				Reporting:  []BugReporting{{Reported: days(0)}, {}},
			},
			period: 20 * day,
		},
		// Special manger and a non-special: normal rules.
		{
			bug: &Bug{
				FirstTime:  days(0),
				LastTime:   days(0),
				NumCrashes: 1,
				HappenedOn: []string{"special-obsoleting", "non-special-manager"},
				Reporting:  []BugReporting{{Reported: days(0)}},
			},
			period: 100 * day,
		},
		// Happened a lot: min period.
		{
			bug: &Bug{
				FirstTime:  days(0),
				LastTime:   days(1),
				NumCrashes: 1000,
				Reporting:  []BugReporting{{Reported: days(0)}},
			},
			period: 80 * day,
		},
	}
	for i, test := range tests {
		test.bug.Namespace = "test1"
		got := test.bug.obsoletePeriod()
		if got != test.period {
			t.Errorf("test #%v: got: %.2f, want %.2f",
				i, float64(got/time.Hour)/24, float64(test.period/time.Hour)/24)
		}
	}
}

func TestEmailNotifObsoleted(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Maintainers = []string{"maintainer@syzkaller.com"}
	c.client2.ReportCrash(crash)
	report := c.pollEmailBug()
	// Need to upstream so that it's not auto-upstreamed before obsoleted.
	c.incomingEmail(report.Sender, "#syz upstream")
	report = c.pollEmailBug()
	// Add more people to bug CC.
	c.incomingEmail(report.Sender, "wow", EmailOptCC([]string{"somebody@else.com"}))

	// Bug is open, new crashes don't create new bug.
	c.client2.ReportCrash(crash)
	c.expectNoEmail()

	// Not yet.
	c.advanceTime(59 * 24 * time.Hour)
	c.expectNoEmail()

	// Now!
	c.advanceTime(2 * 24 * time.Hour)
	notif := c.pollEmailBug()
	if !strings.Contains(notif.Body, "Auto-closing this bug as obsolete") {
		t.Fatalf("bad notification text: %q", notif.Body)
	}
	c.expectEQ(notif.To, []string{"bugs@syzkaller.com", "default@sender.com", "somebody@else.com"})

	// New crash must create new bug.
	c.client2.ReportCrash(crash)
	report = c.pollEmailBug()
	c.expectEQ(report.Subject, "title1 (2)")
	// Now the same, but for the last reporting (must have smaller CC list).
	c.incomingEmail(report.Sender, "#syz upstream")
	report = c.pollEmailBug()
	c.incomingEmail(report.Sender, "#syz upstream")
	report = c.pollEmailBug()

	c.advanceTime(101 * 24 * time.Hour)
	notif = c.pollEmailBug()
	if !strings.Contains(notif.Body, "Auto-closing this bug as obsolete") {
		t.Fatalf("bad notification text: %q", notif.Body)
	}
	c.expectEQ(notif.To, []string{"bugs2@syzkaller.com"})
}

func TestEmailNotifNotObsoleted(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	// Crashes with repro are not auto-obsoleted.
	crash1 := testCrash(build, 1)
	crash1.ReproSyz = []byte("repro")
	c.client2.ReportCrash(crash1)
	report1 := c.pollEmailBug()
	c.incomingEmail(report1.Sender, "#syz upstream")
	report1 = c.pollEmailBug()

	// This crash will get another crash later.
	crash2 := testCrash(build, 2)
	c.client2.ReportCrash(crash2)
	report2 := c.pollEmailBug()
	c.incomingEmail(report2.Sender, "#syz upstream")
	report2 = c.pollEmailBug()

	// This crash will get some activity later.
	crash3 := testCrash(build, 3)
	c.client2.ReportCrash(crash3)
	report3 := c.pollEmailBug()
	c.incomingEmail(report3.Sender, "#syz upstream")
	report3 = c.pollEmailBug()

	// This will be obsoleted (just to check that we have timings right).
	c.advanceTime(24 * time.Hour)
	crash4 := testCrash(build, 4)
	c.client2.ReportCrash(crash4)
	report4 := c.pollEmailBug()
	c.incomingEmail(report4.Sender, "#syz upstream")
	report4 = c.pollEmailBug()

	c.advanceTime(59 * 24 * time.Hour)
	c.expectNoEmail()

	c.client2.ReportCrash(crash2)
	c.incomingEmail(report3.Sender, "I am looking at it")

	c.advanceTime(5 * 24 * time.Hour)
	// Only crash 4 is obsoleted.
	notif := c.pollEmailBug()
	c.expectEQ(notif.Sender, report4.Sender)
	c.expectNoEmail()

	// Crash 3 also obsoleted after some time.
	c.advanceTime(20 * 24 * time.Hour)
	notif = c.pollEmailBug()
	c.expectEQ(notif.Sender, report3.Sender)
}

func TestEmailNotifObsoletedManager(t *testing.T) {
	// Crashes with repro are auto-obsoleted if happen on a particular manager only.
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	build.Manager = "no-fix-bisection-manager"
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	report := c.pollEmailBug()
	c.incomingEmail(report.Sender, "#syz upstream")
	report = c.pollEmailBug()
	c.advanceTime(200 * 24 * time.Hour)
	notif := c.pollEmailBug()
	c.expectTrue(strings.Contains(notif.Body, "Auto-closing this bug as obsolete"))
}

func TestExtNotifUpstreamEmbargo(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusOpen,
	})
	c.expectEQ(reply.OK, true)
	c.client.pollNotifs(0)
	c.advanceTime(20 * 24 * time.Hour)
	notif := c.client.pollNotifs(1)[0]
	c.expectEQ(notif.ID, rep.ID)
	c.expectEQ(notif.Type, dashapi.BugNotifUpstream)
}

func TestExtNotifUpstreamOnHold(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep := c.client.pollBug()

	// Specify fixing commit for the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusOpen,
		OnHold: true,
	})
	c.expectEQ(reply.OK, true)
	c.advanceTime(20 * 24 * time.Hour)
	c.client.pollNotifs(0)
}
