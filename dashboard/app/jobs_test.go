// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
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
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink, logLink))
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
compiler:       compiler1
patch:          %[1]v

`, patchLink, kernelConfigLink))
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
compiler:       compiler1
patch:          %[3]v

`, truncatedError, errorLink, patchLink, kernelConfigLink))
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
