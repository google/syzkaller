// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
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
		msg := <-c.emailSink
		to := email.MergeEmailLists([]string{"test@requester.com", "somebody@else.com", mailingList})
		c.expectEQ(msg.To, to)
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 3)
		c.expectEQ(msg.Attachments[0].Name, "patch.diff")
		c.expectEQ(msg.Attachments[0].Data, []byte(patch))
		c.expectEQ(msg.Attachments[1].Name, "raw.log.txt")
		c.expectEQ(msg.Attachments[1].Data, jobDoneReq.CrashLog)
		c.expectEQ(msg.Attachments[2].Name, "config.txt")
		c.expectEQ(msg.Attachments[2].Data, build.KernelConfig)
		body := `Hello,

syzbot has tested the proposed patch but the reproducer still triggered crash:
test crash title

test crash report

Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch is attached.
Kernel config is attached.
Raw console output is attached.

`
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
	}
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
		msg := <-c.emailSink
		c.expectEQ(len(msg.Attachments), 2)
		c.expectEQ(msg.Attachments[0].Name, "patch.diff")
		c.expectEQ(msg.Attachments[0].Data, []byte(patch))
		c.expectEQ(msg.Attachments[1].Name, "config.txt")
		c.expectEQ(msg.Attachments[1].Data, build.KernelConfig)
		body := `Hello,

syzbot tried to test the proposed patch but build/boot failed:

failed to apply patch


Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch is attached.
Kernel config is attached.


`
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
	}

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch, EmailOptMessageID(3))
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	jobDoneReq = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Build: *build,
	}
	c.expectOK(c.API(client2, key2, "job_done", jobDoneReq, nil))
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	{
		msg := <-c.emailSink
		c.expectEQ(len(msg.Attachments), 2)
		c.expectEQ(msg.Attachments[0].Name, "patch.diff")
		c.expectEQ(msg.Attachments[0].Data, []byte(patch))
		c.expectEQ(msg.Attachments[1].Name, "config.txt")
		c.expectEQ(msg.Attachments[1].Data, build.KernelConfig)
		body := fmt.Sprintf(`Hello,

syzbot has tested the proposed patch and the reproducer did not trigger crash:

Reported-and-tested-by: syzbot+%v@testapp.appspotmail.com

Note: the tag will also help syzbot to understand when the bug is fixed.

Tested on repo1/branch1 commit
kernel_commit1 (Sat Feb 3 04:05:06 0001 +0000)
kernel_commit_title1

compiler: compiler1
Patch is attached.
Kernel config is attached.


---
There is no WARRANTY for the result, to the extent permitted by applicable law.
Except when otherwise stated in writing syzbot provides the result "AS IS"
without warranty of any kind, either expressed or implied, but not limited to,
the implied warranties of merchantability and fittness for a particular purpose.
The entire risk as to the quality of the result is with you. Should the result
prove defective, you assume the cost of all necessary servicing, repair or
correction.
`, extBugID)
		if msg.Body != body {
			t.Fatalf("got email body:\n%s\n\nwant:\n%s", msg.Body, body)
		}
	}

	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	c.expectEQ(pollResp.ID, "")
}
