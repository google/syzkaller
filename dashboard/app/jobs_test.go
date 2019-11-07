// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	db "google.golang.org/appengine/datastore"
)

func TestJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	patch := `--- a/mm/kasan/kasan.c
+++ b/mm/kasan/kasan.c
-       current->kasan_depth++;
+       current->kasan_depth--;
`

	// Report crash without repro, check that test requests are not accepted.
	crash := testCrash(build, 1)
	crash.Maintainers = []string{"maintainer@kernel.org"}
	c.client2.ReportCrash(crash)

	sender := c.pollEmailBug().Sender
	c.incomingEmail(sender, "#syz upstream\n")
	sender = c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)
	mailingList := config.Namespaces["test2"].Reporting[1].Config.(*EmailConfig).Email
	c.incomingEmail(sender, "bla-bla-bla", EmailOptFrom("maintainer@kernel.org"),
		EmailOptCC([]string{mailingList, "kernel@mailing.list"}))

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body := c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "This crash does not have a reproducer"), true)

	// Report crash with repro.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	c.client2.ReportCrash(crash)
	c.client2.pollAndFailBisectJob(build.Manager)

	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "syzbot has found a reproducer"), true)

	c.incomingEmail(sender, "#syz test: repo",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch commit",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "does not look like a valid git repo"), true)

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptFrom("\"foo\" <blAcklisteD@dOmain.COM>"))
	c.expectNoEmail()
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// This submits actual test request.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com"}))
	c.expectNoEmail()

	// A dup of the same request with the same Message-ID.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com"}))
	c.expectNoEmail()

	pollResp = c.client2.pollJobs("foobar")
	c.expectEQ(pollResp.ID, "")
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://git.git/git.git")
	c.expectEQ(pollResp.KernelBranch, "kernel-branch")
	c.expectEQ(pollResp.KernelConfig, build.KernelConfig)
	c.expectEQ(pollResp.SyzkallerCommit, build.SyzkallerCommit)
	c.expectEQ(pollResp.Patch, []byte(patch))
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts"))
	c.expectEQ(pollResp.ReproSyz, []byte("repro syz"))
	c.expectEQ(pollResp.ReproC, []byte("repro C"))

	pollResp2 := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp2, pollResp)

	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	c.client2.JobDone(jobDoneReq)

	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		logLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
		msg := c.pollEmailBug()
		to := email.MergeEmailLists([]string{"test@requester.com", "somebody@else.com", mailingList})
		c.expectEQ(msg.To, to)
		c.expectEQ(msg.Subject, "Re: "+crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch but the reproducer still triggered crash:
test crash title

test crash report

Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[3]v
kernel config:  %[2]v
dashboard link: https://testapp.appspot.com/bug?extid=%[4]v
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, logLink, extBugID))
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
		c.checkURLContents(logLink, jobDoneReq.CrashLog)
	}

	// Testing fails with an error.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(2))
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: []byte("failed to apply patch"),
	}
	c.client2.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but build/boot failed:

failed to apply patch


Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
kernel config:  %[2]v
dashboard link: https://testapp.appspot.com/bug?extid=%[3]v
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, extBugID))
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	// Testing fails with a huge error that can't be inlined in email.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(3))
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: bytes.Repeat([]byte{'a', 'b', 'c'}, (maxInlineError+100)/3),
	}
	c.client2.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		errorLink := externalLink(c.ctx, textError, dbJob.Error)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		truncatedError := string(jobDoneReq.Error[len(jobDoneReq.Error)-maxInlineError:])
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but build/boot failed:

%[1]v

Error text is too large and was truncated, full error text is at:
%[2]v


Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
kernel config:  %[4]v
dashboard link: https://testapp.appspot.com/bug?extid=%[5]v
compiler:       compiler1
patch:          %[3]v

`, truncatedError, errorLink, patchLink, kernelConfigLink, extBugID))
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(errorLink, jobDoneReq.Error)
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(4))
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
	}
	c.client2.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger crash:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
patch:          %[2]v

Note: testing is done by a robot and is best-effort only.
`, extBugID, patchLink, kernelConfigLink))
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

// Test on particular commit and without a patch.
func TestJobWithoutPatch(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	c.client2.ReportCrash(crash)
	c.client2.pollAndFailBisectJob(build.Manager)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	c.incomingEmail(sender, "#syz test git://mygit.com/git.git 5e6a2eea\n", EmailOptMessageID(1))
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	testBuild := testBuild(2)
	testBuild.KernelRepo = "git://mygit.com/git.git"
	testBuild.KernelBranch = ""
	testBuild.KernelCommit = "5e6a2eea5e6a2eea5e6a2eea5e6a2eea5e6a2eea"
	jobDoneReq := &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *testBuild,
	}
	c.client2.JobDone(jobDoneReq)
	{
		_, dbBuild, _ := c.loadJob(pollResp.ID)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger crash:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Tested on:

commit:         5e6a2eea kernel_commit_title2
git tree:       git://mygit.com/git.git
kernel config:  %[2]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler2

Note: testing is done by a robot and is best-effort only.
`, extBugID, kernelConfigLink))
		c.checkURLContents(kernelConfigLink, testBuild.KernelConfig)
	}

	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

// Test on a restricted manager.
func TestJobRestrictedManager(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	build.Manager = "restricted-manager"
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproSyz = []byte("repro syz")
	c.client2.ReportCrash(crash)
	c.client2.pollAndFailBisectJob(build.Manager)
	sender := c.pollEmailBug().Sender

	// Testing on a wrong repo must fail and no test jobs passed to manager.
	c.incomingEmail(sender, "#syz test: git://mygit.com/git.git master\n", EmailOptMessageID(1))
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "you should test only on restricted.git"), true)
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// Testing on the right repo must succeed.
	c.incomingEmail(sender, "#syz test: git://restricted.git/restricted.git master\n", EmailOptMessageID(2))
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://restricted.git/restricted.git")
}

// Test that JobBisectFix is returned only after 30 days
func TestBisectFixJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// Receive the JobBisectCause
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixJob:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Ensure no more jobs
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectEQ(resp.ID, "")

	// Advance time by 30 days and read out any notification emails
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report upstream."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following crash"))
	}

	// Ensure that we get a JobBisectFix
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixJob:JobBisectFix"),
	}
	c.client2.expectOK(c.client2.JobDone(done))
}

// Test that JobBisectFix jobs are re-tried if crash occurs on ToT
func TestBisectFixRetry(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// Receive the JobBisectCause
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Advance time by 30 days and read out any notification emails
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report upstream."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following crash"))
	}

	// Ensure that we get a JobBisectFix. We send back a crashlog, no error, no commits
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		Build: dashapi.Build{
			ID: "build1",
		},
		ID:          resp.ID,
		CrashLog:    []byte("this is a crashlog"),
		CrashReport: []byte("this is a crashreport"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Advance time by 30 days. No notification emails
	{
		c.advanceTime(30 * 24 * time.Hour)
	}

	// Ensure that we get a JobBisectFix retry
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectFix"),
	}
	c.client2.expectOK(c.client2.JobDone(done))
}

// Test that bisection results are not reported for bugs that are already marked as fixed.
func TestNotReportingAlreadyFixed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report.
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// Receive the JobBisectCause.
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	sender := ""
	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report upstream."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following crash"))
		sender = msg.Sender
	}

	// Poll for a BisectFix job.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)

	// Meanwhile, the bug is marked as fixed separately.
	c.incomingEmail(sender, "#syz fix: kernel: add a fix", EmailOptCC(nil))

	{
		// Email notification of "Your 'fix:' command is accepted, but please keep
		// bugs@syzkaller.com mailing list in CC next time."
		c.client2.pollEmailBug()
	}

	// At this point, send back the results for the BisectFix job also.
	done = &dashapi.JobDoneReq{
		ID:          resp.ID,
		Build:       *build,
		Log:         []byte("bisectfix log 4"),
		CrashTitle:  "bisectfix crash title 4",
		CrashLog:    []byte("bisectfix crash log 4"),
		CrashReport: []byte("bisectfix crash report 4"),
		Commits: []dashapi.Commit{
			{
				Hash:       "46e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a fix",
				Author:     "author@kernel.org",
				AuthorName: "Author Kernelov",
				CC: []string{
					"reviewer1@kernel.org", "\"Reviewer2\" <reviewer2@kernel.org>",
					// These must be filtered out:
					"syzbot@testapp.appspotmail.com",
					"syzbot+1234@testapp.appspotmail.com",
					"\"syzbot\" <syzbot+1234@testapp.appspotmail.com>",
				},
				Date: time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	c.expectOK(c.client2.JobDone(done))

	// No reporting should come in at this point. If there is reporting, c.Close()
	// will fail.
}

// Test that fix bisections are listed on the bug page if the bug.BisectFix
// is not BisectYes.
func TestFixBisectionsListed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// Receive the JobBisectCause.
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// At this point, no fix bisections should be listed out.
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
	c.expectEQ(err, nil)
	c.expectEQ(len(bugs), 1)
	url := fmt.Sprintf("/bug?id=%v", keys[0].StringID())
	content, err := c.httpRequest("GET", url, "", AccessAdmin)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("All fix bisections")))

	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report upstream."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following crash"))
	}

	// Ensure that we get a JobBisectFix. We send back a crashlog, no error,
	// no commits.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		Build: dashapi.Build{
			ID: "build1",
		},
		ID:          resp.ID,
		CrashTitle:  "this is a crashtitle",
		CrashLog:    []byte("this is a crashlog"),
		CrashReport: []byte("this is a crashreport"),
		Log:         []byte("this is a log"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Check the bug page and ensure that a bisection is listed out.
	content, err = c.httpRequest("GET", url, "", AccessAdmin)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("Fix bisection attempts")))

	// Advance time by 30 days. No notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
	}

	// Ensure that we get a JobBisectFix retry.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectFix"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Check the bug page and ensure that no bisections are listed out.
	content, err = c.httpRequest("GET", url, "", AccessAdmin)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("All fix bisections")))
}

// Test that fix bisections do not occur if Repo has NoFixBisections set.
func TestFixBisectionsDisabled(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report
	build := testBuild(1)
	build.Manager = "no-fix-bisection-manager"
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 20)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// Receive the JobBisectCause.
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixRetry:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title20")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report upstream."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title20")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following crash"))
	}

	// Ensure that we do not get a JobBisectFix.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectEQ(resp.ID, "")
}
