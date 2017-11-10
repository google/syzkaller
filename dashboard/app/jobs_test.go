// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
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
	c.expectOK(c.API(client2, key2, "report_crash", crash, nil))

	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	sender := (<-c.emailSink).Sender

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch)
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "This crash does not have a reproducer"), true)

	// Report crash with repro.
	crash.Maintainers = []string{"foo@bar.com"}
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	c.expectOK(c.API(client2, key2, "report_crash", crash, nil))

	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "syzkaller has found reproducer"), true)

	c.incomingEmail(sender, "#syz test: repo")
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch commit")
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "want 2 args"), true)

	c.incomingEmail(sender, "#syz test: repo branch")
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "does not look like a valid git repo"), true)

	c.incomingEmail(sender, "#syz test: git://git.git/git.git master")
	c.expectEQ(len(c.emailSink), 1)
	c.expectEQ(strings.Contains((<-c.emailSink).Body, "I don't see any patch attached to the request"), true)

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch)
	c.expectOK(c.GET("/email_poll"))
	c.expectEQ(len(c.emailSink), 0)

	pollResp := new(dashapi.JobPollResp)
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{"foobar"}}, pollResp))
	c.expectEQ(pollResp.ID, "")
	c.expectOK(c.API(client2, key2, "job_poll", &dashapi.JobPollReq{[]string{build.Manager}}, pollResp))
	c.expectEQ(pollResp.ID != "", true)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelRepo, "git://git.git/git.git")
	c.expectEQ(pollResp.KernelBranch, "kernel-branch")
	c.expectEQ(pollResp.KernelConfig, build.KernelConfig)
	c.expectEQ(pollResp.SyzkallerCommit, build.SyzkallerCommit)
	c.expectEQ(pollResp.Patch, []byte(patch+"\n"))
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
		list := config.Namespaces["test2"].Reporting[0].Config.(*EmailConfig).Email
		c.expectEQ(msg.To, []string{"default@sender.com", list})
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 3)
		c.expectEQ(msg.Attachments[0].Name, "config.txt")
		c.expectEQ(msg.Attachments[0].Data, build.KernelConfig)
		c.expectEQ(msg.Attachments[1].Name, "patch.txt")
		c.expectEQ(msg.Attachments[1].Data, []byte(patch+"\n"))
		c.expectEQ(msg.Attachments[2].Name, "raw.log")
		c.expectEQ(msg.Attachments[2].Data, jobDoneReq.CrashLog)
		c.expectEQ(msg.Body, `Hello,

syzbot has tested the proposed patch but the reproducer still triggered crash:
test crash title

test crash report

Tested on commit kernel_commit1
repo1/branch1
compiler: compiler1
Patch and kernel config are attached.
Raw console output is attached.

`)
	}
	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch)
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
		c.expectEQ(msg.Attachments[0].Name, "config.txt")
		c.expectEQ(msg.Attachments[0].Data, build.KernelConfig)
		c.expectEQ(msg.Attachments[1].Name, "patch.txt")
		c.expectEQ(msg.Attachments[1].Data, []byte(patch+"\n"))
		c.expectEQ(msg.Body, `Hello,

syzbot tried to test the proposed patch but build failed:

failed to apply patch

Tested on commit kernel_commit1
repo1/branch1
compiler: compiler1
Patch and kernel config are attached.


`)
	}

	c.incomingEmail(sender, "#syz test: git://git.git/git.git kernel-branch\n"+patch)
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
		c.expectEQ(msg.Attachments[0].Name, "config.txt")
		c.expectEQ(msg.Attachments[0].Data, build.KernelConfig)
		c.expectEQ(msg.Attachments[1].Name, "patch.txt")
		c.expectEQ(msg.Attachments[1].Data, []byte(patch+"\n"))
		c.expectEQ(msg.Body, `Hello,

syzbot has tested the proposed patch and the reproducer did not trigger crash:

Tested-by: syzbot <syzkaller@googlegroups.com>

Once the fix is committed, please reply to this email with:
#syz fix: exact-commit-title

Tested on commit kernel_commit1
repo1/branch1
compiler: compiler1
Patch and kernel config are attached.


---
There is no WARRANTY for the result, to the extent permitted by applicable law.
Except when otherwise stated in writing syzbot provides the result "AS IS"
without warranty of any kind, either expressed or implied, but not limited to,
the implied warranties of merchantability and fittness for a particular purpose.
The entire risk as to the quality of the result is with you. Should the result
prove defective, you assume the cost of all necessary servicing, repair or
correction.
`)
	}
}
