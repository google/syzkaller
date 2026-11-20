// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/appengine/v2"
)

const sampleGitPatch = `--- a/mm/kasan/kasan.c
+++ b/mm/kasan/kasan.c
-       current->kasan_depth++;
+       current->kasan_depth--;
`

const syzTestGitBranchSamplePatch = "#syz test: git://git.git/git.git kernel-branch\n" + sampleGitPatch

// nolint: funlen
func TestJob(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	appID := appengine.AppID(c.ctx)
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

	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "syzbot has found a reproducer"), true)

	c.incomingEmail(sender, "#syz test: repo",
		EmailOptFrom("test@requester.com"), EmailOptSubject("my-subject"), EmailOptCC([]string{mailingList}))
	msg := c.pollEmailBug()

	c.expectEQ(strings.Contains(msg.Body, replyMalformedSyzTest), true)
	c.expectEQ(msg.Subject, "Re: my-subject")

	c.incomingEmail(sender, "#syz test: repo branch commit",
		EmailOptFrom("test@requester.com"), EmailOptSubject("Re: my-subject"), EmailOptCC([]string{mailingList}))
	msg = c.pollEmailBug()
	c.expectEQ(strings.Contains(msg.Body, replyMalformedSyzTest), true)
	c.expectEQ(msg.Subject, "Re: my-subject")

	c.incomingEmail(sender, "#syz test: repo branch",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	body = c.pollEmailBug().Body
	c.expectEQ(strings.Contains(body, "does not look like a valid git repo"), true)

	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("\"foo\" <blOcKed@dOmain.COM>"))
	c.expectNoEmail()
	pollResp := c.globalClient.pollJobs(build.Manager)
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

	pollResp = c.globalClient.pollJobs("foobar")
	c.expectEQ(pollResp.ID, "")
	pollResp = c.globalClient.pollJobs(build.Manager)
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
		`# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#repro opts
repro syz`))
	c.expectEQ(pollResp.ReproC, []byte("repro C"))

	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	c.globalClient.JobDone(jobDoneReq)

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
dashboard link: https://%[5]v.appspot.com/bug?extid=%[4]v
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, logLink, extBugID, appID))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
		c.checkURLContents(logLink, jobDoneReq.CrashLog)
	}

	// Testing fails with an error.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(2))
	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: []byte("failed to apply patch"),
	}
	c.globalClient.JobDone(jobDoneReq)
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
dashboard link: https://%[4]v.appspot.com/bug?extid=%[3]v
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, extBugID, appID))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	// Testing fails with a huge error that can't be inlined in email.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(3))
	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: bytes.Repeat([]byte{'a', 'b', 'c'}, (maxInlineError+100)/3),
	}
	c.globalClient.JobDone(jobDoneReq)
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
dashboard link: https://%[6]v.appspot.com/bug?extid=%[5]v
compiler:       compiler1
patch:          %[3]v

`, truncatedError, errorLink, patchLink, kernelConfigLink, extBugID, appID))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(errorLink, jobDoneReq.Error)
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	c.incomingEmail(sender, syzTestGitBranchSamplePatch, EmailOptMessageID(4))
	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	jobDoneReq = &dashapi.JobDoneReq{
		ID:       pollResp.ID,
		Build:    *build,
		CrashLog: []byte("console output"),
	}
	c.globalClient.JobDone(jobDoneReq)
	{
		dbJob, dbBuild, _ := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		logLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger any issue:

Reported-by: syzbot+%[1]v@%[5]v.appspotmail.com
Tested-by: syzbot+%[1]v@%[5]v.appspotmail.com

Tested on:

commit:         11111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[4]v
kernel config:  %[3]v
dashboard link: https://%[5]v.appspot.com/bug?extid=%[1]v
compiler:       compiler1
patch:          %[2]v

Note: testing is done by a robot and is best-effort only.
`, extBugID, patchLink, kernelConfigLink, logLink, appID))
		c.checkURLContents(patchLink, []byte(sampleGitPatch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

// Test whether we can test boot time crashes.
func TestBootErrorPatch(t *testing.T) {
	c := NewSpannerCtx(t)
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
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
}

const testErrorTitle = `upstream test error: WARNING in __queue_work`

func TestTestErrorPatch(t *testing.T) {
	c := NewSpannerCtx(t)
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
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
}

// Test on particular commit and without a patch.
func TestJobWithoutPatch(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	appID := appengine.AppID(c.ctx)
	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	// Patch testing should happen for bugs with fix commits too.
	c.incomingEmail(sender, "#syz fix: some commit title\n")

	c.incomingEmail(sender, "#syz test git://mygit.com/git.git 5e6a2eea\n", EmailOptMessageID(1))
	c.expectNoEmail()
	pollResp := c.globalClient.pollJobs(build.Manager)
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
	c.globalClient.JobDone(jobDoneReq)
	{
		_, dbBuild, _ := c.loadJob(pollResp.ID)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := c.pollEmailBug()
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger any issue:

Reported-by: syzbot+%[1]v@%[3]v.appspotmail.com
Tested-by: syzbot+%[1]v@%[3]v.appspotmail.com

Tested on:

commit:         5e6a2eea kernel_commit_title2
git tree:       git://mygit.com/git.git
kernel config:  %[2]v
dashboard link: https://%[3]v.appspot.com/bug?extid=%[1]v
compiler:       compiler2

Note: no patches were applied.
Note: testing is done by a robot and is best-effort only.
`, extBugID, kernelConfigLink, appID))
		c.checkURLContents(kernelConfigLink, testBuild.KernelConfig)
	}

	pollResp = c.globalClient.pollJobs(build.Manager)
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
	c.expectEQ(bug.ReproLevelVal(), ReproLevelC)

	// Let's say that the C repro testing has failed.
	c.advanceTime(c.config().Obsoleting.ReproRetestStart + time.Hour)
	for range 2 {
		resp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
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
		client.expectOK(c.globalClient.JobDone(done))
	}
	// Expect that the repro level is no longer ReproLevelC.
	c.expectNoEmail()
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevelVal(), ReproLevelSyz)
	// Let's also deprecate the syz repro.
	c.advanceTime(c.config().Obsoleting.ReproRetestPeriod + time.Hour)

	resp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	c.expectEQ(resp.Type, dashapi.JobTestPatch)
	c.expectEQ(resp.KernelBranch, build.KernelBranch)
	c.expectEQ(resp.ReproC, []uint8(nil))
	c.expectEQ(resp.KernelConfig, build.KernelConfig)
	done := &dashapi.JobDoneReq{
		ID: resp.ID,
	}
	client.expectOK(c.globalClient.JobDone(done))
	// Expect that the repro level is no longer ReproLevelC.
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevelVal(), ReproLevelNone)
	c.expectEQ(bug.ReproLevelVal(), ReproLevelC)
	// Expect that the bug gets deprecated.
	notif := c.pollEmailBug()
	require.Contains(t, notif.Body, "Auto-closing this bug as obsolete")
	// Expect that the right obsoletion reason was set.
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.StatusReason, dashapi.InvalidatedByRevokedRepro)
}

func TestCOnlyReproRetestJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	oldBuild := testBuild(1)
	oldBuild.KernelRepo = "git://mygit.com/git.git"
	oldBuild.KernelBranch = "main"
	client.UploadBuild(oldBuild)

	crash := testCrash(oldBuild, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproC = []byte("repro C")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	c.advanceTime(time.Minute)
	build := testBuild(1)
	build.ID = "new-build"
	build.KernelRepo = "git://mygit.com/new-git.git"
	build.KernelBranch = "new-main"
	build.KernelConfig = []byte{0xAB, 0xCD, 0xEF}
	client.UploadBuild(build)

	c.advanceTime(time.Hour)
	bug, _, _ := c.loadBug(extBugID)
	c.expectEQ(bug.ReproLevelVal(), ReproLevelC)
	c.expectEQ(bug.HeadReproLevelVal(), ReproLevelC)
	c.expectEQ(bug.HasCRepro, true)
	c.expectEQ(bug.HasSyzRepro, false)
	c.expectEQ(bug.HeadHasCRepro, true)
	c.expectEQ(bug.HeadHasSyzRepro, false)

	// Let's say that the C repro testing has failed.
	c.advanceTime(c.config().Obsoleting.ReproRetestStart + time.Hour)
	resp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	c.expectEQ(resp.Type, dashapi.JobTestPatch)
	c.expectEQ(resp.KernelRepo, build.KernelRepo)
	c.expectEQ(resp.KernelBranch, build.KernelBranch)
	c.expectEQ(resp.KernelConfig, build.KernelConfig)
	c.expectEQ(resp.Patch, []uint8(nil))
	c.expectNE(resp.ReproC, []uint8(nil))
	c.expectEQ(resp.ReproSyz, []uint8(nil))

	// Pretend that the C repro fails.
	done := &dashapi.JobDoneReq{
		ID: resp.ID,
	}
	client.expectOK(c.globalClient.JobDone(done))

	// Expect that the repro level is now ReproLevelNone.
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevelVal(), ReproLevelNone)
	c.expectEQ(bug.ReproLevelVal(), ReproLevelC)
	c.expectEQ(bug.HasCRepro, true)
	c.expectEQ(bug.HasSyzRepro, false)
	c.expectEQ(bug.HeadHasCRepro, false)
	c.expectEQ(bug.HeadHasSyzRepro, false)

	// Expect that the bug gets deprecated.
	c.advanceTime(c.config().Obsoleting.MaxPeriod + time.Hour)
	notif := c.pollEmailBug()
	require.Contains(t, notif.Body, "Auto-closing this bug as obsolete")
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

	resp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	c.expectEQ(resp.Type, dashapi.JobTestPatch)
	c.expectEQ(resp.KernelRepo, build.KernelRepo)
	c.expectEQ(resp.KernelBranch, build.KernelBranch)
	c.expectEQ(resp.KernelConfig, build.KernelConfig)
	c.expectEQ(resp.Patch, []uint8(nil))

	// Pretend that the C repro fails.
	done := &dashapi.JobDoneReq{
		ID: resp.ID,
	}

	client.expectOK(c.globalClient.JobDone(done))

	// If it has worked, the repro is revoked and the bug is obsoleted.
	c.pollEmailBug()
	bug, _, _ := c.loadBug(extBugID)
	c.expectEQ(bug.HeadReproLevelVal(), ReproLevelNone)
}

// Test on a restricted manager.
func TestJobRestrictedManager(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	build.Manager = restrictedManager
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproSyz = []byte("repro syz")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender

	// Testing on a wrong repo must fail and no test jobs passed to manager.
	c.incomingEmail(sender, "#syz test: git://mygit.com/git.git master\n", EmailOptMessageID(1))
	reply := c.pollEmailBug()
	c.expectEQ(strings.Contains(reply.Body, "you should test only on restricted.git"), true)
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// Testing on the right repo must succeed.
	c.incomingEmail(sender, "#syz test: git://restricted.git/restricted.git master\n", EmailOptMessageID(2))
	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://restricted.git/restricted.git")
}

// Test that fix bisections are listed on the bug page if bug.BisectFix is not BisectYes.
func TestFixBisectionsListed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	_, bugKey := c.loadSingleBug()
	url := fmt.Sprintf("/bug?id=%v", bugKey.StringID())
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("Fix bisection attempts")))

	c.saveHistoricalBisectJob(historicalBisectJob{
		bugKey:      bugKey,
		jobType:     JobBisectFix,
		build:       &dashapi.Build{ID: "build1"},
		crashTitle:  "this is a crashtitle",
		crashLog:    "this is a crashlog",
		crashReport: "this is a crashreport",
		log:         "this is a log",
	})

	content, err = c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("Fix bisection attempts")))
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
	reports, err := c.globalClient.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
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
	pollResp := c.globalClient.pollJobs(build.Manager)
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
	err = c.globalClient.JobDone(jobDoneReq)
	c.expectOK(err)

	// Verify that we do get the bug update about the completed request.
	jobDoneUpdates, err := c.globalClient.ReportingPollBugs("test")
	c.expectOK(err)
	c.expectEQ(len(jobDoneUpdates.Reports), 1)

	newReport := jobDoneUpdates.Reports[0]
	c.expectEQ(newReport.Type, dashapi.ReportTestPatch)
	c.expectEQ(newReport.CrashTitle, "test crash title")
	c.expectEQ(newReport.Report, []byte("test crash report"))

	// Confirm the patch testing result.
	reply, _ = c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
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
	reports, err := c.globalClient.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
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
	reports, err := c.globalClient.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	ret, err := c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
		BugID: origReport.ID,
		User:  "developer@kernel.org",
		Patch: []byte(sampleGitPatch),
	})
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure branch and repo are correct.
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.KernelRepo, build.KernelRepo)
	c.expectEQ(pollResp.KernelBranch, build.KernelBranch)
}

func TestParallelJobs(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := c.globalClient.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)
	c.expectEQ(len(reports.Reports), 1)

	reply, _ := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
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
	ret, err := c.globalClient.NewTestJob(testPatchReq)
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure the job will be passed to the job processor.
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, repo1)

	// This job is already taken, there are no other jobs.
	emptyPollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})

	// Create another job.
	testPatchReq.Repo = repo2
	ret, err = c.globalClient.NewTestJob(testPatchReq)
	c.expectOK(err)
	c.expectEQ(ret.ErrorText, "")

	// Make sure the new job will be passed to the job processor.
	pollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, repo2)

	// .. and then there'll be no other jobs.
	emptyPollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})

	// Emulate a syz-ci restart.
	c.globalClient.JobReset(&dashapi.JobResetReq{Managers: []string{build.Manager}})

	// .. and re-query both jobs.
	repos := []string{}
	for range 2 {
		pollResp = c.globalClient.pollJobs(build.Manager)
		c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
		repos = append(repos, pollResp.KernelRepo)
	}
	assert.ElementsMatch(t, repos, []string{repo1, repo2}, "two patch testing requests are expected")

	// .. but nothing else is to be expected.
	emptyPollResp = c.globalClient.pollJobs(build.Manager)
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
	err = c.globalClient.JobDone(jobDoneReq)
	c.expectOK(err)
	c.globalClient.pollBugs(1)

	// .. and make sure it doesn't appear again.
	emptyPollResp = c.globalClient.pollJobs(build.Manager)
	c.expectEQ(emptyPollResp, &dashapi.JobPollResp{})
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
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelRepo, build.KernelRepo)
	c.expectEQ(pollResp.KernelBranch, build.KernelBranch)
	c.expectEQ(pollResp.Patch, []byte(sampleGitPatch))
}

func TestAliasPatchTestingJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 2)
	crash.Title = testErrorTitle
	client.ReportCrash(crash)

	// Confirm the report.
	reports, err := c.globalClient.ReportingPollBugs("test")
	origReport := reports.Reports[0]
	c.expectOK(err)

	reply, _ := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
		ID:     origReport.ID,
		Status: dashapi.BugStatusOpen,
	})
	client.expectEQ(reply.Error, false)
	client.expectEQ(reply.OK, true)

	// Create a new patch testing job.
	_, err = c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
		BugID:  origReport.ID,
		User:   "developer@kernel.org",
		Branch: "some-branch",
		Repo:   "repo10alias",
		Patch:  []byte(sampleGitPatch),
	})
	c.expectOK(err)

	// Make sure branch and repo are correct.
	pollResp := c.globalClient.pollJobs(build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://syzkaller.org")
	c.expectEQ(pollResp.KernelBranch, "some-branch")
}

func TestReproCJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client

	build := testBuild(1)
	build.KernelRepo = "git://syzkaller.org"
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	rep := c.globalClient.pollBug()

	// Upload a more recent failed build on the manager to ensure
	// handleTestReproCRequest still selects the last successful build.
	c.advanceTime(time.Hour)
	failedBuild := testBuild(2)
	failedBuild.Manager = build.Manager
	failedBuild.KernelRepo = build.KernelRepo
	failedBuild.KernelCommitDate = failedBuild.KernelCommitDate.Add(time.Hour)
	c.expectOK(client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *failedBuild,
		Crash: dashapi.Crash{
			Title: "kernel build failed",
		},
	}))

	bug, _, _ := c.loadBug(rep.ID)
	reproC := []byte("void main() { *(int*)0 = 0; }")
	job, _, err := handleTestReproCRequest(c.ctx, &testReproCReqArgs{
		bug:     bug,
		bugKey:  bug.key(c.ctx),
		user:    "test@user.com",
		manager: build.Manager,
		reproC:  reproC,
	})
	c.expectOK(err)
	c.expectNE(job, nil)
	c.expectEQ(job.Type, JobTestPatch)

	// Manager polls job with TestPatches = true.
	pollResp, err := c.globalClient.JobPoll(&dashapi.JobPollReq{
		Managers: map[string]dashapi.ManagerJobs{
			build.Manager: {TestPatches: true},
		},
	})
	c.expectOK(err)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)
	c.expectEQ(pollResp.KernelBranch, build.KernelCommit)
	c.expectEQ(string(pollResp.ReproC), string(reproC))

	// Job succeeds with a different crash title that matches the bug via AltTitles.
	jobDoneReq := &dashapi.JobDoneReq{
		ID:             pollResp.ID,
		Build:          *testBuild(2),
		CrashTitle:     "different crash title",
		CrashAltTitles: []string{rep.Title},
	}
	c.expectOK(c.globalClient.JobDone(jobDoneReq))

	// The newly added repro must cause a new report via pollBug().
	rep2 := c.globalClient.pollBug()
	c.expectEQ(rep2.Type, dashapi.ReportRepro)
	c.expectEQ(string(rep2.ReproC), string(reproC))
	c.expectNE(rep2.ReproCLink, "")

	bug, _, _ = c.loadBug(rep.ID)
	c.expectEQ(bug.HasCRepro, true)
	c.expectTrue(slices.Contains(bug.AltTitles, "different crash title"))
}

func TestReproCJobError(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	build.KernelRepo = "git://syzkaller.org"
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	c.expectOK(err)

	bug, _, _ := c.loadBug(extBugID)
	bugKey := bug.key(c.ctx)
	c.expectEQ(bug.HasCRepro, false)

	reproC := []byte("void main() { *(int*)0 = 0; }")
	_, _, err = handleTestReproCRequest(c.ctx, &testReproCReqArgs{
		bug:     bug,
		bugKey:  bugKey,
		user:    "test@user.com",
		manager: build.Manager,
		reproC:  reproC,
	})
	c.expectOK(err)

	pollResp, err := c.globalClient.JobPoll(&dashapi.JobPollReq{
		Managers: map[string]dashapi.ManagerJobs{
			build.Manager: {TestPatches: true},
		},
	})
	c.expectOK(err)

	// Job finishes with req.Error and a CrashTitle.
	jobDoneReq := &dashapi.JobDoneReq{
		ID:         pollResp.ID,
		Build:      *testBuild(2),
		CrashTitle: bug.Title,
		Error:      []byte("infrastructure error"),
	}
	c.expectOK(c.globalClient.JobDone(jobDoneReq))

	// No reproducer reporting should occur, and HasCRepro should remain false.
	c.expectNoEmail()
	bug, _, _ = c.loadBug(extBugID)
	c.expectEQ(bug.HasCRepro, false)
}

// Test that patch testing can be disabled with a message for a specific reporting stage.
func TestDisableTestCommandWithMessage(t *testing.T) {
	// Job polling needs Spanner.
	c := NewSpannerCtx(t)
	defer c.Close()

	const disabledMessage = "Patch testing is temporarily disabled."
	c.transformContext = func(ctx context.Context) context.Context {
		return contextWithConfig(ctx, replaceReporting(ctx, "access-public-email",
			"access-public-email-reporting1", func(r Reporting) Reporting {
				r.DisableTestCommand = &DisableTestCommandConfig{Message: disabledMessage}
				return r
			}))
	}

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	require.NoError(t, err)

	// The report about the found reproducer must not advertise #syz test.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	client.ReportCrash(crash)
	body := c.pollEmailBug().Body
	assert.Contains(t, body, "syzbot has found a reproducer")
	assert.NotContains(t, body, "#syz test")
	assert.NotContains(t, body, "---")

	// Both well-formed and malformed commands get the configured reply.
	mailingList := c.config().Namespaces["access-public-email"].Reporting[0].Config.(*EmailConfig).Email
	for _, cmd := range []string{syzTestGitBranchSamplePatch, "#syz test: repo\n"} {
		c.incomingEmail(sender, cmd, EmailOptFrom("test@requester.com"),
			EmailOptCC([]string{mailingList}))
		reply := c.pollEmailBug()
		assert.Contains(t, reply.Body, disabledMessage)
	}

	// Blocked users still get no reply.
	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptFrom("\"foo\" <blOcKed@dOmain.COM>"), EmailOptCC([]string{mailingList}))
	c.expectNoEmail()

	// The external API is also affected.
	ret, err := c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
		BugID:  extBugID,
		User:   "developer@kernel.org",
		Branch: "kernel-branch",
		Repo:   "git://git.git/git.git",
		Patch:  []byte(sampleGitPatch),
	})
	require.NoError(t, err)
	assert.Equal(t, disabledMessage, ret.ErrorText)

	// No test jobs were created.
	pollResp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	assert.Empty(t, pollResp.ID)
}

// Test that patch testing can be silently disabled for the whole namespace,
// while the internally generated test jobs keep working.
func TestDisableTestCommandSilently(t *testing.T) {
	// Job polling needs Spanner.
	c := NewSpannerCtx(t)
	defer c.Close()

	c.transformContext = func(ctx context.Context) context.Context {
		return contextWithConfig(ctx, replaceNamespaceConfig(ctx, "access-public-email",
			func(cfg *Config) *Config {
				ret := *cfg
				ret.DisableTestCommand = &DisableTestCommandConfig{}
				return &ret
			}))
	}

	client := c.publicClient
	build := testBuild(1)
	// Needed for the repro retesting jobs.
	build.KernelRepo = "git://mygit.com/git.git"
	build.KernelBranch = "main"
	client.UploadBuild(build)

	crash := testCrashWithRepro(build, 1)
	client.ReportCrash(crash)
	msg := c.pollEmailBug()
	assert.Contains(t, msg.Body, "syz repro:")
	assert.NotContains(t, msg.Body, "#syz test")
	sender := msg.Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	require.NoError(t, err)

	// The commands are silently ignored.
	mailingList := c.config().Namespaces["access-public-email"].Reporting[0].Config.(*EmailConfig).Email
	for _, cmd := range []string{syzTestGitBranchSamplePatch, "#syz test: repo\n"} {
		c.incomingEmail(sender, cmd, EmailOptFrom("test@requester.com"),
			EmailOptCC([]string{mailingList}))
		c.expectNoEmail()
	}

	// The external API still gets an error.
	ret, err := c.globalClient.NewTestJob(&dashapi.TestPatchRequest{
		BugID:  extBugID,
		User:   "developer@kernel.org",
		Branch: "kernel-branch",
		Repo:   "git://git.git/git.git",
		Patch:  []byte(sampleGitPatch),
	})
	require.NoError(t, err)
	assert.Equal(t, "patch testing is disabled", ret.ErrorText)

	// No test jobs were created.
	pollResp := c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	assert.Empty(t, pollResp.ID)

	// But the reproducer retesting jobs are still generated.
	c.advanceTime(c.config().Obsoleting.ReproRetestStart + time.Hour)
	pollResp = c.globalClient.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{TestPatches: true})
	assert.NotEmpty(t, pollResp.ID)
	assert.Equal(t, dashapi.JobTestPatch, pollResp.Type)
}

func TestTestCommandDisabledConfig(t *testing.T) {
	nsDisabled := &DisableTestCommandConfig{}
	stageDisabled := &DisableTestCommandConfig{Message: "disabled"}
	cfg := &Config{
		Reporting: []Reporting{
			{Name: "stage1"},
			{Name: "stage2", DisableTestCommand: stageDisabled},
		},
	}
	// The per-stage setting does not leak into other stages.
	assert.Nil(t, cfg.testCommandDisabled("stage1"))
	assert.Equal(t, stageDisabled, cfg.testCommandDisabled("stage2"))

	// The namespace setting applies to the stages without own setting.
	cfg.DisableTestCommand = nsDisabled
	assert.Equal(t, nsDisabled, cfg.testCommandDisabled("stage1"))
	assert.Equal(t, stageDisabled, cfg.testCommandDisabled("stage2"))
	assert.Equal(t, nsDisabled, cfg.testCommandDisabled("unknown"))
}
