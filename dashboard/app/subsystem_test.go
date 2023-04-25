// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
)

const subsystemTestNs = "test1"

func TestSubsytemMaintainers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// This also indirectly tests getSubsystemService.
	assert.ElementsMatch(t,
		subsystemMaintainers(c.ctx, subsystemTestNs, "subsystemA"),
		[]string{
			"subsystemA@list.com", "subsystemA@person.com",
		},
	)
	assert.ElementsMatch(t, subsystemMaintainers(c.ctx, subsystemTestNs, "does-not-exist"), []string{})
}

func TestPeriodicSubsystemRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 1)
	crash := testCrash(build, 1)
	crash.Title = "WARNING: abcd"
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	// Keep revision the same.
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID) // Not enough time has passed yet.

	// Wait until the refresh period is over.
	c.advanceTime(openBugsUpdateTime)

	_, err = c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func TestOpenBugRevRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 0)
	crash := testCrash(build, 1)
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	c.advanceTime(time.Hour)
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	// Update the revision number as well.
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func TestClosedBugSubsystemRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 0)
	crash := testCrash(build, 1)
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// "Fix" the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	})
	c.expectEQ(reply.OK, true)
	build2 := testBuild(2)
	build2.Manager = build.Manager
	build2.Commits = []string{"foo: fix the crash"}
	client.UploadBuild(build2)
	client.pollNotifs(0)
	bug, _, _ := c.loadBug(rep.ID)
	c.expectEQ(bug.Status, BugStatusFixed)

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	c.advanceTime(time.Hour)
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func TestUserSubsystemsRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublicEmail, keyPublicEmail, true)
	ns := "access-public-email"

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug with subsystemA.
	crash := testCrash(build, 1)
	crash.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash)
	c.incomingEmail(c.pollEmailBug().Sender, "#syz upstream\n")

	sender := c.pollEmailBug().Sender
	_, extID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	// Make sure we've set the right subsystem.
	expectSubsystems(t, client, extID, "subsystemA")

	// Manually set another subsystem.
	c.incomingEmail(sender, "#syz set subsystems: subsystemB\n",
		EmailOptFrom("test@requester.com"))
	c.pollEmailBug()
	expectSubsystems(t, client, extID, "subsystemB")

	// Refresh subsystems.
	c.advanceTime(openBugsUpdateTime + time.Hour)
	_, err = c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)

	// The subsystem must stay the same.
	expectSubsystems(t, client, extID, "subsystemB")

	// Bump the subsystem revision and refresh subsystems.
	c.setSubsystems(ns, testSubsystems, 2)
	c.advanceTime(time.Hour)
	_, err = c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)

	// The subsystem must still stay the same.
	expectSubsystems(t, client, extID, "subsystemB")
}

func expectSubsystems(t *testing.T, client *apiClient, extID string, subsystems ...string) {
	t.Helper()
	bug, _, _ := client.Ctx.loadBug(extID)
	names := []string{}
	for _, item := range bug.Tags.Subsystems {
		names = append(names, item.Name)
	}
	assert.ElementsMatch(t, names, subsystems)
}

// nolint: goconst
func TestPeriodicSubsystemReminders(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientSubsystemRemind, keySubsystemRemind, true)
	build := testBuild(1)
	client.UploadBuild(build)

	bugToExtID := map[string]string{}

	// WARNING: a first (3 crashes)
	aFirst := testCrash(build, 1)
	aFirst.Title = `WARNING: a first`
	aFirst.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aFirst)
	bugToExtID[aFirst.Title] = client.pollEmailExtID()
	for i := 0; i < 2; i++ {
		client.ReportCrash(aFirst)
		c.advanceTime(time.Hour)
	}

	// WARNING: a second (1 crash)
	aSecond := testCrash(build, 1)
	aSecond.Title = `WARNING: a second`
	aSecond.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aSecond)
	bugToExtID[aSecond.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// WARNING: b first (1 crashes)
	bFirst := testCrash(build, 1)
	bFirst.Title = `WARNING: b first`
	bFirst.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(bFirst)
	bugToExtID[bFirst.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// WARNING: b first (5 crashes)
	bSecond := testCrash(build, 1)
	bSecond.Title = `WARNING: b second`
	bSecond.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(bSecond)
	bugToExtID[bSecond.Title] = client.pollEmailExtID()
	for i := 0; i < 4; i++ {
		client.ReportCrash(bSecond)
		c.advanceTime(time.Hour)
	}

	// Report bugs once more to pretend they're still valid.
	c.advanceTime(time.Hour * 24 * 14)
	client.ReportCrash(aFirst)
	client.ReportCrash(bFirst)
	client.ReportCrash(aSecond)
	client.ReportCrash(bSecond)
	c.advanceTime(time.Hour)

	// Make sure we don't report crashes at other reporting stages.
	crash := testCrash(build, 1)
	crash.Title = `WARNING: a third, keep private` // see the config in app_test.go
	crash.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash)
	client.pollBug()
	c.advanceTime(time.Hour)

	_, err := c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	// Expect the reminder for subsystemA.
	reply := client.pollEmailBug()
	c.expectEQ(reply.Subject, "[moderation] Monthly subsystemA report (Jan 2000)")
	c.expectEQ(reply.To, []string{"moderation@syzkaller.com"})
	c.expectEQ(reply.Cc, []string(nil))
	c.expectEQ(reply.Body, fmt.Sprintf(`Hello subsystemA maintainers/developers,

This is a 30-day syzbot report for the subsystemA subsystem.
All related reports/information can be found at:
https://testapp.appspot.com/subsystem-reminders/s/subsystemA

During the period, 2 new issues were detected and 0 were fixed.
In total, 2 issues are still open.

Some of the still happening issues:

Crashes Repro Title
4       No    WARNING: a first
              https://testapp.appspot.com/bug?extid=%[1]v
2       No    WARNING: a second
              https://testapp.appspot.com/bug?extid=%[2]v

The report will be sent to: [subsystemA@list.com subsystemA@person.com].
If the report looks fine to you, please send the "syz upstream" command.

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.
`, bugToExtID["WARNING: a first"], bugToExtID["WARNING: a second"]))

	// Expect the reminder for subsystemB.
	reply = client.pollEmailBug()
	c.expectEQ(reply.Subject, "[moderation] Monthly subsystemB report (Jan 2000)")
	c.expectEQ(reply.To, []string{"moderation@syzkaller.com"})
	c.expectEQ(reply.Cc, []string(nil))
	c.expectEQ(reply.Body, fmt.Sprintf(`Hello subsystemB maintainers/developers,

This is a 30-day syzbot report for the subsystemB subsystem.
All related reports/information can be found at:
https://testapp.appspot.com/subsystem-reminders/s/subsystemB

During the period, 2 new issues were detected and 0 were fixed.
In total, 2 issues are still open.

Some of the still happening issues:

Crashes Repro Title
6       No    WARNING: b second
              https://testapp.appspot.com/bug?extid=%[1]v
2       No    WARNING: b first
              https://testapp.appspot.com/bug?extid=%[2]v

The report will be sent to: [subsystemB@list.com subsystemB@person.com].
If the report looks fine to you, please send the "syz upstream" command.

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.
`, bugToExtID["WARNING: b second"], bugToExtID["WARNING: b first"]))

	// Wait the next pair of reminders.
	c.advanceTime(time.Hour * 24 * 31)
	_, err = c.GET("/cron/subsystem_reports")
	c.expectOK(err)
}

func TestSubsystemRemindersModeration(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientSubsystemRemind, keySubsystemRemind, true)
	build := testBuild(1)
	client.UploadBuild(build)
	bugToExtID := map[string]string{}

	aFirst := testCrash(build, 1)
	aFirst.Title = `WARNING: a first`
	aFirst.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aFirst)
	bugToExtID[aFirst.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	aSecond := testCrash(build, 1)
	aSecond.Title = `WARNING: a second`
	aSecond.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aSecond)
	bugToExtID[aSecond.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// Report them again.
	c.advanceTime(time.Hour * 24 * 14)
	client.ReportCrash(aFirst)
	client.ReportCrash(aSecond)

	_, err := c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	// Expect the reminder for subsystemA.
	replyA := client.pollEmailBug()
	c.expectEQ(replyA.Subject, "[moderation] Monthly subsystemA report (Jan 2000)")

	// Moderate the subsystemA list.
	c.advanceTime(time.Hour)
	c.incomingEmail(replyA.Sender, "#syz upstream\n")
	// Also emulate the second email that would come from the mailing list.
	// The email should be silently ignored.
	c.incomingEmail(replyA.Sender, "#syz upstream\n",
		EmailOptFrom("moderation@syzkaller.com"), EmailOptOrigFrom("user@user.com"))

	// Expect the normal report.
	reply := client.pollEmailBug()
	c.expectEQ(reply.Subject, "[syzbot] Monthly subsystemA report (Jan 2000)")
	c.expectEQ(reply.To, []string{"bugs@syzkaller.com", "subsystemA@list.com", "subsystemA@person.com"})
	c.expectEQ(reply.Cc, []string(nil))
	c.expectEQ(reply.Body, fmt.Sprintf(`Hello subsystemA maintainers/developers,

This is a 30-day syzbot report for the subsystemA subsystem.
All related reports/information can be found at:
https://testapp.appspot.com/subsystem-reminders/s/subsystemA

During the period, 2 new issues were detected and 0 were fixed.
In total, 2 issues are still open.

Some of the still happening issues:

Crashes Repro Title
2       No    WARNING: a first
              https://testapp.appspot.com/bug?extid=%[1]v
2       No    WARNING: a second
              https://testapp.appspot.com/bug?extid=%[2]v

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.
`, bugToExtID["WARNING: a first"], bugToExtID["WARNING: a second"]))
}

func TestSubsystemReportGeneration(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientSubsystemRemind, keySubsystemRemind, true)
	build := testBuild(1)
	client.UploadBuild(build)
	bugToExtID := map[string]string{}

	// This crash will be too old.
	crash := testCrash(build, 1)
	crash.Title = `WARNING: old crash`
	crash.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash)
	client.pollEmailBug()
	c.advanceTime(time.Hour * 24 * 40)

	// Emulate one fixed bug.
	aFixed := testCrash(build, 1)
	aFixed.Title = `WARNING: fixed bug`
	aFixed.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aFixed)
	bugToExtID[aFixed.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)
	updReply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         bugToExtID[aFixed.Title],
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix1"},
	})
	c.expectEQ(updReply.OK, true)
	c.expectOK(client.UploadCommits([]dashapi.Commit{
		{Hash: "hash1", Title: "foo: fix1", Date: timeNow(c.ctx)},
	}))

	allCrashes := []*dashapi.Crash{}

	// Report 4 crashes with a reproducer.
	var biggestReproCrash *dashapi.Crash
	for i := 2; i <= 5; i++ {
		crash := testCrash(build, 1)
		crash.Title = fmt.Sprintf(`WARNING: has repro %d`, i+1)
		crash.GuiltyFiles = []string{"a.c"}
		client.ReportCrash(crash)
		bugToExtID[crash.Title] = client.pollEmailExtID()
		c.advanceTime(time.Hour)

		crash.ReproOpts = []byte("some opts")
		crash.ReproSyz = []byte("getpid()")
		client.ReportCrash(crash)
		client.pollEmailBug()
		c.advanceTime(time.Hour)

		for j := 3; j <= i; j++ {
			client.ReportCrash(crash)
			c.advanceTime(time.Hour)
		}
		allCrashes = append(allCrashes, crash)
		biggestReproCrash = crash
	}

	// Report 5 crashes without a reproducer.
	for i := 1; i <= 5; i++ {
		crash := testCrash(build, 1)
		crash.Title = fmt.Sprintf(`WARNING: no repro %d`, i+1)
		crash.GuiltyFiles = []string{"a.c"}
		client.ReportCrash(crash)
		bugToExtID[crash.Title] = client.pollEmailExtID()
		c.advanceTime(time.Hour)

		for j := 2; j <= i; j++ {
			client.ReportCrash(crash)
			c.advanceTime(time.Hour)
		}
		allCrashes = append(allCrashes, crash)
	}

	c.advanceTime(time.Hour * 24 * 14)
	for _, crash := range allCrashes {
		client.ReportCrash(crash)
		c.advanceTime(time.Hour)
	}

	// Now query the report.
	_, err := c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	reply := client.pollEmailBug()
	c.expectEQ(reply.Subject, "[moderation] Monthly subsystemA report (Feb 2000)")
	c.expectEQ(reply.To, []string{"moderation@syzkaller.com"})
	c.expectEQ(reply.Cc, []string(nil))
	c.expectEQ(reply.Body, fmt.Sprintf(`Hello subsystemA maintainers/developers,

This is a 30-day syzbot report for the subsystemA subsystem.
All related reports/information can be found at:
https://testapp.appspot.com/subsystem-reminders/s/subsystemA

During the period, 9 new issues were detected and 1 were fixed.
In total, 10 issues are still open and 1 has been fixed so far.

Some of the still happening issues:

Crashes Repro Title
6       Yes   WARNING: has repro 6
              https://testapp.appspot.com/bug?extid=%[1]v
6       No    WARNING: no repro 6
              https://testapp.appspot.com/bug?extid=%[2]v
5       Yes   WARNING: has repro 5
              https://testapp.appspot.com/bug?extid=%[3]v
5       No    WARNING: no repro 5
              https://testapp.appspot.com/bug?extid=%[4]v
4       Yes   WARNING: has repro 4
              https://testapp.appspot.com/bug?extid=%[5]v
3       Yes   WARNING: has repro 3
              https://testapp.appspot.com/bug?extid=%[6]v

The report will be sent to: [subsystemA@list.com subsystemA@person.com].
If the report looks fine to you, please send the "syz upstream" command.

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.
`,
		bugToExtID["WARNING: has repro 6"],
		bugToExtID["WARNING: no repro 6"],
		bugToExtID["WARNING: has repro 5"],
		bugToExtID["WARNING: no repro 5"],
		bugToExtID["WARNING: has repro 4"],
		bugToExtID["WARNING: has repro 3"],
	))

	// Add one more crash and regenerate.
	client.ReportCrash(biggestReproCrash)
	c.advanceTime(time.Hour)

	c.incomingEmail(reply.Sender, "#syz regenerate\n")
	c.advanceTime(time.Hour)

	_, err = c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	secondReply := client.pollEmailBug()
	c.expectEQ(secondReply.Subject, "[moderation] Monthly subsystemA report (Feb 2000)")
	c.expectNE(reply.Sender, secondReply.Sender)
	c.expectTrue(strings.Contains(secondReply.Body, `7       Yes   WARNING: has repro 6`))
}

func TestSubsystemRemindersNoReport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientSubsystemRemind, keySubsystemRemind, true)
	build := testBuild(1)
	client.UploadBuild(build)

	cFirst := testCrash(build, 1)
	cFirst.Title = `WARNING: c first`
	cFirst.GuiltyFiles = []string{"c.c"}
	client.ReportCrash(cFirst)
	client.pollEmailBug()
	c.advanceTime(time.Hour)

	cSecond := testCrash(build, 1)
	cSecond.Title = `WARNING: c second`
	cSecond.GuiltyFiles = []string{"c.c"}
	client.ReportCrash(cSecond)
	client.pollEmailBug()
	c.advanceTime(time.Hour)

	// Report them again.
	c.advanceTime(time.Hour * 24 * 14)
	client.ReportCrash(cFirst)
	client.ReportCrash(cSecond)

	_, err := c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	// Expect no reminders for subsystemC.
	client.expectNoEmail()
}

// nolint: goconst
func TestNoRemindersWithDiscussions(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientSubsystemRemind, keySubsystemRemind, true)
	build := testBuild(1)
	client.UploadBuild(build)

	bugToExtID := map[string]string{}

	// WARNING: a first
	aFirst := testCrash(build, 1)
	aFirst.Title = `WARNING: a first`
	aFirst.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aFirst)
	bugToExtID[aFirst.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// WARNING: a second (1 crash)
	aSecond := testCrash(build, 1)
	aSecond.Title = `WARNING: a second`
	aSecond.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aSecond)
	bugToExtID[aSecond.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// WARNING: a third (1 crash)
	aThird := testCrash(build, 1)
	aThird.Title = `WARNING: a third`
	aThird.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(aThird)
	bugToExtID[aThird.Title] = client.pollEmailExtID()
	c.advanceTime(time.Hour)

	// Report bugs once more to pretend they're still valid.
	c.advanceTime(time.Hour * 24 * 10)
	client.ReportCrash(aFirst)
	client.ReportCrash(aSecond)
	client.ReportCrash(aThird)

	// Add a recent discussion to the second bug.
	c.expectOK(client.SaveDiscussion(&dashapi.SaveDiscussionReq{
		Discussion: &dashapi.Discussion{
			ID:      "123",
			Source:  dashapi.DiscussionLore,
			Type:    dashapi.DiscussionReport,
			Subject: "Some discussion",
			BugIDs:  []string{bugToExtID[aSecond.Title]},
			Messages: []dashapi.DiscussionMessage{
				{
					ID:       "123",
					External: true,
					Time:     timeNow(c.ctx),
				},
			},
		},
	}))
	c.advanceTime(time.Hour)

	_, err := c.GET("/cron/subsystem_reports")
	c.expectOK(err)

	reply := client.pollEmailBug()
	// Verify that the second bug is not present.
	c.expectEQ(reply.Body, fmt.Sprintf(`Hello subsystemA maintainers/developers,

This is a 30-day syzbot report for the subsystemA subsystem.
All related reports/information can be found at:
https://testapp.appspot.com/subsystem-reminders/s/subsystemA

During the period, 3 new issues were detected and 0 were fixed.
In total, 3 issues are still open.

Some of the still happening issues:

Crashes Repro Title
2       No    WARNING: a first
              https://testapp.appspot.com/bug?extid=%[1]v
2       No    WARNING: a third
              https://testapp.appspot.com/bug?extid=%[2]v

The report will be sent to: [subsystemA@list.com subsystemA@person.com].
If the report looks fine to you, please send the "syz upstream" command.

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.
`, bugToExtID["WARNING: a first"], bugToExtID["WARNING: a third"]))
}
