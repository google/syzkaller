// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/stretchr/testify/assert"
	db "google.golang.org/appengine/v2/datastore"
)

const sampleGitPatch = `--- a/mm/kasan/kasan.c
+++ b/mm/kasan/kasan.c
-       current->kasan_depth++;
+       current->kasan_depth--;
`

const syzTestGitBranchSamplePatch = "#syz test: git://git.git/git.git kernel-branch\n" + sampleGitPatch

// nolint: funlen
func TestJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	// Report crash without repro, check that test requests are not accepted.
	crash := testCrash(build, 1)
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	sender := c.pollEmailBug().Sender
	c.incomingEmail(sender, "#syz upstream\n")
	sender = c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)
	mailingList := c.config().Namespaces["access-public-email"].Reporting[0].Config.(*EmailConfig).Email
	c.incomingEmail(sender, "bla-bla-bla", EmailOptFrom("maintainer@kernel.org"),
		EmailOptCC([]string{mailingList, "kernel@mailing.list"}))

	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body := c.pollEmailBug().Body
	t.Logf("body: %s", body)
	c.expectEQ(strings.Contains(body, "This crash does not have a reproducer"), true)

	// Report crash with repro.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	client.ReportCrash(crash)
	client.pollAndFailBisectJob(build.Manager)

	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "syzbot has found a reproducer"), true)

	c.incomingEmail(sender, "#syz test: repo",
		EmailOptFrom("test@requester.com"), EmailOptSubject("my-subject"), EmailOptCC([]string{mailingList}))
	msg := c.pollEmailBug()
	c.expectEQ(strings.Contains(msg.Body, "want either no args or 2 args"), true)
	c.expectEQ(msg.Subject, "Re: my-subject")

	c.incomingEmail(sender, "#syz test: repo branch commit",
		EmailOptFrom("test@requester.com"), EmailOptSubject("Re: my-subject"), EmailOptCC([]string{mailingList}))
	msg = c.pollEmailBug()
	c.expectEQ(strings.Contains(msg.Body, "want either no args or 2 args"), true)
	c.expectEQ(msg.Subject, "Re: my-subject")

	c.incomingEmail(sender, "#syz test: repo branch",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "does not look like a valid git repo"), true)

	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("\"foo\" <blOcKed@dOmain.COM>"))
	c.expectNoEmail()
	pollResp := client.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// This submits actual test request.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com", "test@syzkaller.com"}))
	c.expectNoEmail()

	// A dup of the same request with the same Message-ID.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com", "test@syzkaller.com"}))
	c.expectNoEmail()

	pollResp = client.pollJobs("foobar")
	c.expectEQ(pollResp.ID, "")
	pollResp = client.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://git.git/git.git")
	c.expectEQ(pollResp.KernelBranch, "kernel-branch")
	c.expectEQ(pollResp.KernelConfig, build.KernelConfig)
	c.expectEQ(pollResp.SyzkallerCommit, build.SyzkallerCommit)
	c.expectEQ(pollResp.Patch, []byte(sampleGitPatch))
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts"))
	c.expectEQ(pollResp.ReproSyz, []byte(
		"# See https://goo.gl/kgGztJ for information about syzkaller reproducers.\n"+
			"#repro opts\n"+
			"repro syz"))
	c.expectEQ(pollResp.ReproC, []byte("repro C"))

	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	client.JobDone(jobDoneReq)

	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		logLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
		msg := c.pollEmailBug()
		to := email.MergeEmailLists([]string{"test@requester.com", "somebody@else.com", mailingList})
		c.expectEQ(msg.To, to)
		c.expectEQ(msg.Subject, "Re: [syzbot] "+crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch but the reproducer is still triggering an issue:
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
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
		c.checkURLContents(logLink, jobDoneReq.CrashLog)
	}

	// Testing fails with an error.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(2))
	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: []byte("failed to apply patch"),
	}
	client.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but the build/boot failed:

failed to apply patch


Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
kernel config:  %[2]v
dashboard link: https://testapp.appspot.com/bug?extid=%[3]v
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, extBugID))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	// Testing fails with a huge error that can't be inlined in email.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(3))
	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: bytes.Repeat([]byte{'a', 'b', 'c'}, (maxInlineError+100)/3),
	}
	client.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		errorLink := externalLink(c.ctx, textError, dbJob.Error)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		truncatedError := string(jobDoneReq.Error[len(jobDoneReq.Error)-maxInlineError:])
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but the build/boot failed:

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
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(errorLink, jobDoneReq.Error)
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(4))
	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:       pollResp.ID,
		Build:    *build,
		CrashLog: []byte("console output"),
	}
	client.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		logLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger any issue:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[4]v
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
patch:          %[2]v

Note: testing is done by a robot and is best-effort only.
`, extBugID, patchLink, kernelConfigLink, logLink))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

// Test whether we can test boot time crashes.
func TestBootErrorPatch(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = "riscv/fixes boot error: can't ssh into the instance"
	c.client2.ReportCrash(crash)

	report := c.pollEmailBug()
	c.incomingEmail(report.Sender, "#syz upstream\n", EmailOptCC(report.To))
	report = c.pollEmailBug()

	c.incomingEmail(report.Sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("test@requester.com"), EmailOptCC(report.To))
	c.expectNoEmail()
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
}

const testErrorTitle = `upstream test error: WARNING in __queue_work`

func TestTestErrorPatch(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	c.client2.ReportCrash(crash)

	sender := c.pollEmailBug().Sender
	c.incomingEmail(sender, "#syz upstream\n")
	report := c.pollEmailBug()

	c.incomingEmail(report.Sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("test@requester.com"), EmailOptCC(report.To))
	c.expectNoEmail()
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
}

// Test on particular commit and without a patch.
func TestJobWithoutPatch(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	client.ReportCrash(crash)
	client.pollAndFailBisectJob(build.Manager)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	// Patch testing should happen for bugs with fix commits too.
	c.incomingEmail(sender, "#syz fix: some commit title\n")

	c.incomingEmail(sender, "#syz test git://mygit.com/git.git 5e6a2eea\n", EmailOptMessageID(1))
	c.expectNoEmail()
	pollResp := client.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	testBuild := testBuild(2)
	testBuild.KernelRepo = "git://mygit.com/git.git"
	testBuild.KernelBranch = ""
	testBuild.KernelCommit = "5e6a2eea5e6a2eea5e6a2eea5e6a2eea5e6a2eea"
	jobDoneReq := &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *testBuild,
	}
	client.JobDone(jobDoneReq)
	{
		_, dbBuild, _ := c.loadJob(pollResp.ID)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger any issue:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Tested on:

commit:         5e6a2eea kernel_commit_title2
git tree:       git://mygit.com/git.git
kernel config:  %[2]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler2

Note: no patches were applied.
Note: testing is done by a robot and is best-effort only.
`, extBugID, kernelConfigLink))
		c.checkURLContents(kernelConfigLink, testBuild.KernelConfig)
	}

	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

func TestReproRetestJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	oldBuild := testBuild(1)
	oldBuild.KernelRepo = "git://mygit.com/git.git"
	oldBuild.KernelBranch = "main"
	client.UploadBuild(oldBuild)

	crash := testCrash(oldBuild, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	crash2 := testCrash(oldBuild, 1)
	crash2.ReproOpts = []byte("repro opts")
	crash2.ReproSyz = []byte("repro syz")
	crash2.ReproC = []byte("repro C")
	client.ReportCrash(crash2)
	c.pollEmailBug()

	// Upload a newer build.
	c.advanceTime(time.Minute)
	build := testBuild(1)
	build.ID = "new-build"
	build.KernelRepo = "git://mygit.com/new-git.git"
	build.KernelBranch = "new-main"
	build.KernelConfig = []byte{0xAB, 0xCD, 0xEF}
	client.UploadBuild(build)

	c.advanceTime(time.Hour)
	bug, _, _ := c.loadBug(extBugID)
	c.expectEQ(bug.ReproLevel, ReproLevelC)

	// Let's say that the C repro testing has failed.
	c.advanceTime(c.config().Obsoleting.ReproRetestStart + time.Hour)
	for i := 0; i < 2; i++ {
		resp := client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
		c.expectEQ(resp.Type, dashapi.JobTestPatch)
		c.expectEQ(resp.KernelRepo, build.KernelRepo)
		c.expectEQ(resp.KernelBranch, build.KernelBranch)
		c.expectEQ(resp.KernelConfig, build.KernelConfig)
		c.expectEQ(resp.Patch, []uint8(nil))
		var done *dashapi.JobDoneReq
		if resp.ReproC == nil {
			// Pretend that the syz repro still works.
			done = &dashapi.JobDoneReq{
				ID:          resp.ID,
				CrashTitle:  crash.Title,
				CrashLog:    []byte("test crash log"),
				CrashReport: []byte("test crash report"),
			}
		} else {
			// Pretend that the C repro fails.
			done = &dashapi.JobDoneReq{
				ID: resp.ID,
			}
		}
		client.expectOK(client.JobDone(done))
	}
	// Expect that the repro level is no longer ReproLevelC.
	c.expectNoEmail()
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevel, ReproLevelSyz)
	// Let's also deprecate the syz repro.
	c.advanceTime(c.config().Obsoleting.ReproRetestPeriod + time.Hour)

	resp := client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	c.expectEQ(resp.Type, dashapi.JobTestPatch)
	c.expectEQ(resp.KernelBranch, build.KernelBranch)
	c.expectEQ(resp.ReproC, []uint8(nil))
	c.expectEQ(resp.KernelConfig, build.KernelConfig)
	done := &dashapi.JobDoneReq{
		ID: resp.ID,
	}
	client.expectOK(client.JobDone(done))
	// Expect that the repro level is no longer ReproLevelC.
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevel, ReproLevelNone)
	c.expectEQ(bug.ReproLevel, ReproLevelC)
	// Expect that the bug gets deprecated.
	notif := c.pollEmailBug()
	if !strings.Contains(notif.Body, "Auto-closing this bug as obsolete") {
		t.Fatalf("bad notification text: %q", notif.Body)
	}
	// Expect that the right obsoletion reason was set.
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.StatusReason, dashapi.InvalidatedByRevokedRepro)
}

func TestDelegatedManagerReproRetest(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientMgrDecommission, keyMgrDecommission, true)
	oldManager := notYetDecommManger
	newManager := delegateToManager

	oldBuild := testBuild(1)
	oldBuild.KernelRepo = "git://delegated.repo/git.git"
	oldBuild.KernelBranch = "main"
	oldBuild.Manager = oldManager
	client.UploadBuild(oldBuild)

	crash := testCrash(oldBuild, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	// Deprecate the oldManager.
	c.decommissionManager("test-mgr-decommission", oldManager, newManager)

	// Upload a build for the new manager.
	c.advanceTime(time.Minute)
	build := testBuild(1)
	build.ID = "new-build"
	build.KernelRepo = "git://delegated.repo/new-git.git"
	build.KernelBranch = "new-main"
	build.KernelConfig = []byte{0xAB, 0xCD, 0xEF}
	build.Manager = newManager
	client.UploadBuild(build)

	// Wait until the bug is upstreamed.
	c.advanceTime(20 * 24 * time.Hour)
	c.pollEmailBug()
	c.pollEmailBug()

	// Let's say that the C repro testing has failed.
	c.advanceTime(c.config().Obsoleting.ReproRetestPeriod + time.Hour)

	resp := client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	c.expectEQ(resp.Type, dashapi.JobTestPatch)
	c.expectEQ(resp.KernelRepo, build.KernelRepo)
	c.expectEQ(resp.KernelBranch, build.KernelBranch)
	c.expectEQ(resp.KernelConfig, build.KernelConfig)
	c.expectEQ(resp.Patch, []uint8(nil))

	// Pretend that the C repro fails.
	done := &dashapi.JobDoneReq{
		ID: resp.ID,
	}

	client.expectOK(client.JobDone(done))

	// If it has worked, the repro is revoked and the bug is obsoleted.
	c.pollEmailBug()
	bug, _, _ := c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevel, ReproLevelNone)
}

// Test on a restricted manager.
func TestJobRestrictedManager(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	build.Manager = restrictedManager
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproSyz = []byte("repro syz")
	client.ReportCrash(crash)
	client.pollAndFailBisectJob(build.Manager)
	sender := c.pollEmailBug().Sender

	// Testing on a wrong repo must fail and no test jobs passed to manager.
	c.incomingEmail(sender, "#syz test: git://mygit.com/git.git master\n", EmailOptMessageID(1))
	reply := c.pollEmailBug()
	c.expectEQ(strings.Contains(reply.Body, "you should test only on restricted.git"), true)
	pollResp := client.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// Testing on the right repo must succeed.
	c.incomingEmail(sender, "#syz test: git://restricted.git/restricted.git master\n", EmailOptMessageID(2))
	pollResp = client.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://restricted.git/restricted.git")
}

// Test that JobBisectFix is returned only after 30 days.
func TestBisectFixJob(t *testing.T) {
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
		Error: []byte("testBisectFixJob:JobBisectCause"),
	}
	c.client2.expectOK(c.client2.JobDone(done))

	// Ensure no more jobs.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectEQ(resp.ID, "")

	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "[syzbot] title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))
	}

	// Ensure that we get a JobBisectFix.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	done = &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("testBisectFixJob:JobBisectFix"),
	}
	c.client2.expectOK(c.client2.JobDone(done))
}

// Test that JobBisectFix jobs are re-tried if crash occurs on ToT.
func TestBisectFixRetry(t *testing.T) {
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

	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "[syzbot] title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))
	}

	// Ensure that we get a JobBisectFix. We send back a crashlog, no error, no commits.
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
		c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "[syzbot] title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))
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

	// At this point, no fix bisections should be listed out.
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
	c.expectEQ(err, nil)
	c.expectEQ(len(bugs), 1)
	url := fmt.Sprintf("/bug?id=%v", keys[0].StringID())
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("All fix bisections")))

	// Advance time by 30 days and read out any notification emails.
	{
		c.advanceTime(30 * 24 * time.Hour)
		msg := c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "title1")
		c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "[syzbot] title1")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))
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
	content, err = c.GET(url)
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
	content, err = c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("All fix bisections")))
}

// Test that fix bisections do not occur if Repo has NoFixBisections set.
func TestFixBisectionsDisabled(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report.
	build := testBuild(1)
	build.Manager = noFixBisectionManager
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
		c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))

		msg = c.client2.pollEmailBug()
		c.expectEQ(msg.Subject, "[syzbot] title20")
		c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))
	}

	// Ensure that we do not get a JobBisectFix.
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectEQ(resp.ID, "")
}

func TestExternalPatchFlow(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := client.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := client.NewTestJob(&dashapi.TestPatchRequest{
		BugID:  origReport.ID,
		Link:   "http://some-link.com/",
		User:   "developer@kernel.org",
		Branch: "kernel-branch",
		Repo:   "git://git.git/git.git",
		Patch:  []byte(sampleGitPatch),
	})
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure the job will be passed to the job processor.
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, "git://git.git/git.git")
	c.expectEQ(pollResp.KernelBranch, "kernel-branch")
	c.expectEQ(pollResp.Patch, []byte(sampleGitPatch))

	// Emulate the completion of the job.
	build2 := testBuild(2)
	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build2,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	err = c.client2.JobDone(jobDoneReq)
	c.expectOK(err)

	// Verify that we do get the bug update about the completed request.
	jobDoneUpdates, err := client.ReportingPollBugs("test")
	c.expectOK(err)
	c.expectEQ(len(jobDoneUpdates.Reports), 1)

	newReport := jobDoneUpdates.Reports[0]
	c.expectEQ(newReport.Type, dashapi.ReportTestPatch)
	c.expectEQ(newReport.CrashTitle, "test crash title")
	c.expectEQ(newReport.Report, []byte("test crash report"))

	// Confirm the patch testing result.
	reply, _ = client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		JobID:  pollResp.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)
}

func TestExternalPatchTestError(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := client.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := client.NewTestJob(&dashapi.TestPatchRequest{
		BugID:  origReport.ID,
		User:   "developer@kernel.org",
		Branch: "kernel-branch",
		Repo:   "invalid-repo",
		Patch:  []byte(sampleGitPatch),
	})
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, `"invalid-repo" does not look like a valid git repo address.`)
}

func TestExternalPatchCompletion(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	build.KernelRepo = "git://git.git/git.git"
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := client.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := client.NewTestJob(&dashapi.TestPatchRequest{
		BugID: origReport.ID,
		User:  "developer@kernel.org",
		Patch: []byte(sampleGitPatch),
	})
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure branch and repo are correct.
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.KernelRepo, build.KernelRepo)
	c.expectEQ(pollResp.KernelBranch, build.KernelBranch)
}

func TestParallelJobs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := client.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a patch testing job.
	const (
		repo1 = "git://git.git/git1.git"
		repo2 = "git://git.git/git2.git"
	)
	testPatchReq := &dashapi.TestPatchRequest{
		BugID:  origReport.ID,
		Link:   "http://some-link.com/",
		User:   "developer@kernel.org",
		Branch: "kernel-branch",
		Repo:   repo1,
		Patch:  []byte(sampleGitPatch),
	}
	ret, err := client.NewTestJob(testPatchReq)
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure the job will be passed to the job processor.
	pollResp := client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, repo1)

	// This job is already taken, there are no other jobs.
	emptyPollResp := client.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})

	// Create another job.
	testPatchReq.Repo = repo2
	ret, err = client.NewTestJob(testPatchReq)
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure the new job will be passed to the job processor.
	pollResp = client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, repo2)

	// .. and then there'll be no other jobs.
	emptyPollResp = client.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})

	// Emulate a syz-ci restart.
	client.JobReset(&dashapi.JobResetReq{Managers: []string{build.Manager}})

	// .. and re-query both jobs.
	repos := []string{}
	for i := 0; i < 2; i++ {
		pollResp = client.pollJobs(build.Manager)
		c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
		repos = append(repos, pollResp.KernelRepo)
	}
	assert.ElementsMatch(t, repos, []string{repo1, repo2}, "two patch testing requests are expected")

	// .. but nothing else is to be expected.
	emptyPollResp = client.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})

	// Emulate the job's completion.
	build2 := testBuild(2)
	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build2,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	err = client.JobDone(jobDoneReq)
	c.expectOK(err)
	client.pollBugs(1)

	// .. and make sure it doesn't appear again.
	emptyPollResp = client.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})
}

// Test that JobBisectCause jobs are re-tried if there were infra problems.
func TestJobCauseRetry(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client2
	// Upload a crash report.
	build := testBuild(1)
	client.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	client.ReportCrash(crash)
	client.pollEmailBug()

	// Release the report to the second stage.
	c.advanceTime(15 * 24 * time.Hour)
	client.pollEmailBug() // "Sending report to the next stage" email.
	client.pollEmailBug() // New report.

	// Emulate an infra failure.
	resp := client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{
		BisectCause: true,
	})
	client.expectNE(resp.ID, "")
	client.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("infra problem"),
		Flags: dashapi.BisectResultInfraError,
	}
	client.expectOK(client.JobDone(done))
	c.expectNoEmail()

	// Ensure we don't recreate the job right away.
	c.advanceTime(24 * time.Hour)
	resp = client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{
		BisectCause: true,
	})
	client.expectEQ(resp.ID, "")

	// Wait the end of the freeze period.
	c.advanceTime(7 * 24 * time.Hour)
	resp = client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{
		BisectCause: true,
	})
	client.expectNE(resp.ID, "")
	client.expectEQ(resp.Type, dashapi.JobBisectCause)

	done = &dashapi.JobDoneReq{
		ID:          resp.ID,
		Build:       *testBuild(2),
		Log:         []byte("bisect log"),
		CrashTitle:  "bisect crash title",
		CrashLog:    []byte("bisect crash log"),
		CrashReport: []byte("bisect crash report"),
		Commits: []dashapi.Commit{
			{
				Hash:   "36e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:  "kernel: add a bug",
				Author: "author@kernel.org",
				CC:     []string{"user@domain.com"},
				Date:   time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	done.Build.ID = resp.ID
	c.expectOK(client.JobDone(done))

	msg := c.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "syzbot has bisected this issue to:"))
}

// Test that we accept `#syz test` commands without arguments.
func TestEmailTestCommandNoArgs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	build.KernelRepo = "git://git.git/git.git"
	build.KernelBranch = "kernel-branch"
	client.UploadBuild(build)

	crash := testCrashWithRepro(build, 2)
	client.ReportCrash(crash)

	sender := c.pollEmailBug().Sender
	mailingList := c.config().Namespaces["access-public-email"].Reporting[0].Config.(*EmailConfig).Email

	c.incomingEmail(sender, "#syz test\n"+sampleGitPatch,
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectNoEmail()
	pollResp := client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, build.KernelRepo)
	c.expectEQ(pollResp.KernelBranch, build.KernelBranch)
	c.expectEQ(pollResp.Patch, []byte(sampleGitPatch))
}
