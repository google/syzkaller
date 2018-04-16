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
	c.expectOK(c.API(client2, key2, "upload_build", build, nil))

	patch := `--- a/mm/kasan/kasan.c
+++ b/mm/kasan/kasan.c
-       current->kasan_depth++;
+       current->kasan_depth--;
`

	// Report crash without repro, check that test requests are not accepted.
	crash := testCrash(build, 1)
	crash.Maintainers = []string{"maintainer@kernel.org"}
	c.expectOK(c.API(client2, key2, "report_crash", crash, nil))

	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	sender := (<-c.emailSink).Sender
	c.incomingEmail(sender, "#syz upstream\n")
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	sender = (<-c.emailSink).Sender
	_, extBugID, err := email.RemoveAddrContext(sender)
	if err != nil {
		t.Fatal(err)
	}
	mailingList := config.Namespaces["test2"].Reporting[1].Config.(*EmailConfig).Email
	c.incomingEmail(sender, "bla-bla-bla", EmailOptFrom("maintainer@kernel.org"),
		EmailOptCC([]string{mailingList, "kernel@mailing.list"}))

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "This crash does not have a reproducer"), true)

	// Report crash with repro.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	c.expectOK(c.API(client2, key2, "report_crash", crash, nil))

	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "syzbot has found reproducer"), true)

	c.incomingEmail(sender, "#syz test: repo",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch commit",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "does not look like a valid git repo"), true)

	c.incomingEmail(sender, "#syz test: git://git.git/git.git master",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "I don't see any patch attached to the request"), true)

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptFrom("\"foo\" <blAcklisteD@dOmain.COM>"))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 0)
	pollResp := new(dashapi.JobPollResp)
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	c.expectEQ(pollResp.ID, "")

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com"}))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 0)

	// A dup of the same request with the same Message-ID.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com"}))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 0)

	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{"foobar"}}, pollResp))
	c.expectEQ(pollResp.ID, "")
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	c.expectEQ(pollResp.ID != "", true)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://git.git/git.git")
	c.expectEQ(pollResp.KernelBranch, "kernel-branch")
	c.expectEQ(pollResp.KernelConfig, build.KernelConfig)
	c.expectEQ(pollResp.SyzkallerCommit, build.SyzkallerCommit)
	c.expectEQ(pollResp.Patch, []byte(patch))
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts"))
	c.expectEQ(pollResp.ReproSyz, []byte("repro syz"))
	c.expectEQ(pollResp.ReproC, []byte("repro C"))

	pollResp2 := new(dashapi.JobPollResp)
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp2))
	c.expectEQ(pollResp2, pollResp)

	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	c.expectOK(c.API(client2, key2, "job_done", jobDoneReq, nil))

	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	{
		dbJob, dbBuild := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		logLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
		msg := <-c.emailSink
		to := email.MergeEmailLists([]string{"test@requester.com", "somebody@else.com", mailingList})
		c.expectEQ(msg.To, to)
		c.expectEQ(msg.Subject, "Re: "+crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		body := fmt.Sprintf(`Hello,

syzbot has tested the proposed patch but the reproducer still triggered crash:
test crash title

test crash report

Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch: %[1]v
Kernel config: %[2]v
Raw console output: %[3]v

`, patchLink, kernelConfigLink, logLink)
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
		c.checkURLContents(logLink, jobDoneReq.CrashLog)
	}

	// Testing fails with an error.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(2))
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: []byte("failed to apply patch"),
	}
	c.expectOK(c.API(client2, key2, "job_done", jobDoneReq, nil))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	{
		dbJob, dbBuild := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := <-c.emailSink
		c.expectEQ(len(msg.Attachments), 0)
		body := fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but build/boot failed:

failed to apply patch


Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch: %[1]v
Kernel config: %[2]v


`, patchLink, kernelConfigLink)
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	// Testing fails with a huge error that can't be inlined in email.
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(3))
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
		Error: bytes.Repeat([]byte{'a', 'b', 'c'}, (maxInlineError+100)/3),
	}
	c.expectOK(c.API(client2, key2, "job_done", jobDoneReq, nil))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	{
		dbJob, dbBuild := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		errorLink := externalLink(c.ctx, textError, dbJob.Error)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := <-c.emailSink
		c.expectEQ(len(msg.Attachments), 0)
		truncatedError := string(jobDoneReq.Error[len(jobDoneReq.Error)-maxInlineError:])
		body := fmt.Sprintf(`Hello,

syzbot tried to test the proposed patch but build/boot failed:

%[1]v

Error text is too large and was truncated, full error text is at:
%[2]v


Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch: %[3]v
Kernel config: %[4]v


`, truncatedError, errorLink, patchLink, kernelConfigLink)
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(errorLink, jobDoneReq.Error)
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(4))
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
	}
	c.expectOK(c.API(client2, key2, "job_done", jobDoneReq, nil))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	{
		dbJob, dbBuild := c.loadJob(pollResp.ID)
		patchLink := externalLink(c.ctx, textPatch, dbJob.Patch)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		msg := <-c.emailSink
		c.expectEQ(len(msg.Attachments), 0)
		body := fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger crash:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Note: the tag will also help syzbot to understand when the bug is fixed.

Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch: %[2]v
Kernel config: %[3]v


---
There is no WARRANTY for the result, to the extent permitted by applicable law.
Except when otherwise stated in writing syzbot provides the result "AS IS"
without warranty of any kind, either expressed or implied, but not limited to,
the implied warranties of merchantability and fittness for a particular purpose.
The entire risk as to the quality of the result is with you. Should the result
prove defective, you assume the cost of all necessary servicing, repair or
correction.
`, extBugID, patchLink, kernelConfigLink)
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
		c.checkURLContents(patchLink, []byte(patch))
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	c.expectEQ(pollResp.ID, "")
}
