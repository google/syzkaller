// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	db "google.golang.org/appengine/v2/datastore"
)

// nolint: funlen
func TestBisectCause(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrash(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	// No repro - no bisection.
	pollResp := c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")

	// Now upload 4 crashes with repros.
	crash2 := testCrashWithRepro(build, 2)
	c.client2.ReportCrash(crash2)
	msg2 := c.client2.pollEmailBug()

	// This is later, so will be bisected before the previous crash.
	c.advanceTime(time.Hour)
	crash3 := testCrashWithRepro(build, 3)
	c.client2.ReportCrash(crash3)
	c.client2.pollEmailBug()

	// This does not have C repro, so will be bisected after the previous ones.
	c.advanceTime(time.Hour)
	crash4 := testCrashWithRepro(build, 4)
	crash4.Title = "skip reporting2 with repro"
	crash4.ReproC = nil
	c.client2.ReportCrash(crash4)
	msg4 := c.client2.pollEmailBug()

	// This is from a different manager, so won't be bisected.
	c.advanceTime(time.Hour)
	build2 := testBuild(2)
	c.client2.UploadBuild(build2)
	crash5 := testCrashWithRepro(build2, 5)
	c.client2.ReportCrash(crash5)
	c.client2.pollEmailBug()

	// When polling for jobs the expected order is as follows :=
	//		BisectCause #3
	//		BisectCause #2
	//		BisectCause #4
	// After advancing time by 30 days, we get :=
	//		BisectFix   #2
	//		BisectFix   #3
	//		BisectFix   #4

	// BisectCause #3
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobBisectCause)
	c.expectEQ(pollResp.Manager, build.Manager)
	c.expectEQ(pollResp.KernelConfig, build.KernelConfig)
	c.expectEQ(pollResp.SyzkallerCommit, build.SyzkallerCommit)
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts 3"))
	c.expectEQ(pollResp.ReproSyz, []byte(
		"# See https://goo.gl/kgGztJ for information about syzkaller reproducers.\n"+
			"#repro opts 3\n"+
			"syncfs(3)"))
	c.expectEQ(pollResp.ReproC, []byte("int main() { return 3; }"))

	// Bisection failed with an error.
	done := &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Log:   []byte("bisect log 3"),
		Error: []byte("bisect error 3"),
	}
	c.expectOK(c.client2.JobDone(done))
	c.expectNoEmail()

	// BisectCause #2
	pollResp2 := pollResp
	c.advanceTime(time.Minute)
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, pollResp2.ID)
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts 2"))

	// Bisection succeeded.
	jobID := pollResp.ID
	done = &dashapi.JobDoneReq{
		ID:          jobID,
		Build:       *build,
		Log:         []byte("bisect log 2"),
		CrashTitle:  "bisect crash title",
		CrashLog:    []byte("bisect crash log"),
		CrashReport: []byte("bisect crash report"),
		Commits: []dashapi.Commit{
			{
				Hash:       "36e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a bug",
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
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	_, extBugID, err := email.RemoveAddrContext(msg2.Sender)
	c.expectOK(err)
	dbBug, dbCrash, _ := c.loadBug(extBugID)
	reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	reproCLink := externalLink(c.ctx, textReproC, dbCrash.ReproC)
	dbJob, dbBuild, dbJobCrash := c.loadJob(jobID)
	kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
	bisectCrashReportLink := externalLink(c.ctx, textCrashReport, dbJob.CrashReport)
	bisectCrashLogLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
	bisectLogLink := externalLink(c.ctx, textLog, dbJob.Log)
	crashLogLink := externalLink(c.ctx, textCrashLog, dbJobCrash.Log)

	{
		msg := c.pollEmailBug()
		// Not mailed to commit author/cc because !MailMaintainers.
		c.expectEQ(msg.To, []string{"test@syzkaller.com"})
		c.expectEQ(msg.Subject, crash2.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`syzbot has bisected this issue to:

commit 36e65cb4a0448942ec316b24d60446bbd5cc7827
Author: Author Kernelov <author@kernel.org>
Date:   Wed Feb 9 04:05:06 2000 +0000

    kernel: add a bug

bisection log:  %[2]v
start commit:   111111111111 kernel_commit_title1
git tree:       repo1 branch1
final oops:     %[3]v
console output: %[4]v
kernel config:  %[5]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
syz repro:      %[6]v
C reproducer:   %[7]v

Reported-by: syzbot+%[1]v@testapp.appspotmail.com
Fixes: 36e65cb4a044 ("kernel: add a bug")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection
`, extBugID, bisectLogLink, bisectCrashReportLink, bisectCrashLogLink, kernelConfigLink, reproSyzLink, reproCLink))

		syzRepro := []byte(fmt.Sprintf("# https://testapp.appspot.com/bug?id=%v\n%s#%s\n%s",
			dbBug.keyHash(c.ctx), syzReproPrefix, crash2.ReproOpts, crash2.ReproSyz))
		cRepro := []byte(fmt.Sprintf("// https://testapp.appspot.com/bug?id=%v\n%s",
			dbBug.keyHash(c.ctx), crash2.ReproC))
		c.checkURLContents(bisectLogLink, []byte("bisect log 2"))
		c.checkURLContents(bisectCrashReportLink, []byte("bisect crash report"))
		c.checkURLContents(bisectCrashLogLink, []byte("bisect crash log"))
		c.checkURLContents(kernelConfigLink, []byte("config1"))
		c.checkURLContents(reproSyzLink, syzRepro)
		c.checkURLContents(reproCLink, cRepro)
	}

	// The next reporting must get bug report with bisection results.
	c.incomingEmail(msg2.Sender, "#syz upstream")
	{
		msg := c.pollEmailBug()
		_, extBugID2, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)

		c.expectEQ(msg.To, []string{
			"author@kernel.org",
			"bugs@syzkaller.com",
			"default@maintainers.com",
			"reviewer1@kernel.org",
			"reviewer2@kernel.org",
		})
		c.expectEQ(msg.Subject, "[syzbot] "+crash2.Title)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot found the following issue on:

HEAD commit:    111111111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[2]v
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
syz repro:      %[4]v
C reproducer:   %[5]v
CC:             [author@kernel.org reviewer1@kernel.org reviewer2@kernel.org]

The issue was bisected to:

commit 36e65cb4a0448942ec316b24d60446bbd5cc7827
Author: Author Kernelov <author@kernel.org>
Date:   Wed Feb 9 04:05:06 2000 +0000

    kernel: add a bug

bisection log:  %[6]v
final oops:     %[7]v
console output: %[8]v

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com
Fixes: 36e65cb4a044 ("kernel: add a bug")

report2

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
For information about bisection process see: https://goo.gl/tpsmEJ#bisection

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

If you want to overwrite report's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the report is a duplicate of another one, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup`,
			extBugID2, crashLogLink, kernelConfigLink, reproSyzLink, reproCLink,
			bisectLogLink, bisectCrashReportLink, bisectCrashLogLink))
	}

	// BisectCause #4
	// Crash 4 is bisected in reporting with MailMaintainers.
	// It also skipped second reporting because of the title.
	c.incomingEmail(msg4.Sender, "#syz upstream")
	msg4 = c.pollEmailBug()
	c.expectEQ(msg4.To, []string{
		"bugs2@syzkaller.com",
		"default2@maintainers.com",
	})
	c.advanceTime(time.Minute)
	pollResp = c.client2.pollJobs(build.Manager)

	// Bisection succeeded.
	jobID = pollResp.ID
	done = &dashapi.JobDoneReq{
		ID:          jobID,
		Build:       *build,
		Log:         []byte("bisectcause log 4"),
		CrashTitle:  "bisectcause crash title 4",
		CrashLog:    []byte("bisectcause crash log 4"),
		CrashReport: []byte("bisectcause crash report 4"),
		Commits: []dashapi.Commit{
			{
				Hash:       "36e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a bug",
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
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.Subject, crash4.Title)
		c.expectEQ(msg.To, []string{
			"author@kernel.org",
			"bugs2@syzkaller.com",
			"default2@maintainers.com",
			"reviewer1@kernel.org",
			"reviewer2@kernel.org",
		})
	}

	{
		c.advanceTime(30 * 24 * time.Hour)
		subjects := []string{"title3", "title1", "title5", "title3", "title5", "title1"}
		for i := 0; i < 6; i++ {
			msg := c.pollEmailBug()
			if i < 3 {
				c.expectEQ(msg.Subject, subjects[i])
				c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))
			} else {
				c.expectEQ(msg.Subject, "[syzbot] "+subjects[i])
				c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue on"))
			}
		}
	}

	// BisectFix #2
	c.advanceTime(time.Minute)
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobBisectFix)
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts 2"))
	c.advanceTime(5 * 24 * time.Hour)
	done = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Log:   []byte("bisect log 2"),
		Error: []byte("bisect error 2"),
	}
	c.expectOK(c.client2.JobDone(done))

	// BisectFix #3
	c.advanceTime(time.Minute)
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobBisectFix)
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts 3"))
	done = &dashapi.JobDoneReq{
		ID:    pollResp.ID,
		Log:   []byte("bisect log 3"),
		Error: []byte("bisect error 3"),
	}
	c.expectOK(c.client2.JobDone(done))

	// BisectFix #4
	c.advanceTime(time.Minute)
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	c.expectEQ(pollResp.Type, dashapi.JobBisectFix)
	c.expectEQ(pollResp.ReproOpts, []byte("repro opts 4"))
	jobID = pollResp.ID
	done = &dashapi.JobDoneReq{
		ID:          jobID,
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
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	_, extBugID, err = email.RemoveAddrContext(msg4.Sender)
	c.expectOK(err)
	dbBug, dbCrash, _ = c.loadBug(extBugID)
	reproSyzLink = externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	reproCLink = externalLink(c.ctx, textReproC, dbCrash.ReproC)
	dbJob, dbBuild, _ = c.loadJob(jobID)
	kernelConfigLink = externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
	bisectCrashReportLink = externalLink(c.ctx, textCrashReport, dbJob.CrashReport)
	bisectCrashLogLink = externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
	bisectLogLink = externalLink(c.ctx, textLog, dbJob.Log)

	{
		msg := c.pollEmailBug()
		// Not mailed to commit author/cc because !MailMaintainers.
		// c.expectEQ(msg.To, []string{"test@syzkaller.com"})
		c.expectEQ(msg.Subject, crash4.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`syzbot suspects this issue was fixed by commit:

commit 46e65cb4a0448942ec316b24d60446bbd5cc7827
Author: Author Kernelov <author@kernel.org>
Date:   Wed Feb 9 04:05:06 2000 +0000

    kernel: add a fix

bisection log:  %[2]v
start commit:   111111111111 kernel_commit_title1
git tree:       repo1 branch1
final oops:     %[3]v
console output: %[4]v
kernel config:  %[5]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
syz repro:      %[6]v

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: kernel: add a fix

For information about bisection process see: https://goo.gl/tpsmEJ#bisection
`, extBugID, bisectLogLink, bisectCrashReportLink, bisectCrashLogLink, kernelConfigLink, reproSyzLink, reproCLink))

		syzRepro := []byte(fmt.Sprintf("# https://testapp.appspot.com/bug?id=%v\n%s#%s\n%s",
			dbBug.keyHash(c.ctx), syzReproPrefix, crash4.ReproOpts, crash4.ReproSyz))
		c.checkURLContents(bisectLogLink, []byte("bisectfix log 4"))
		c.checkURLContents(bisectCrashReportLink, []byte("bisectfix crash report 4"))
		c.checkURLContents(bisectCrashLogLink, []byte("bisectfix crash log 4"))
		c.checkURLContents(kernelConfigLink, []byte("config1"))
		c.checkURLContents(reproSyzLink, syzRepro)
	}

	// No more bisection jobs.
	pollResp = c.client2.pollJobs(build.Manager)
	c.expectEQ(pollResp.ID, "")
}

func TestBisectCauseInconclusive(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	msg := c.client2.pollEmailBug()

	pollResp := c.client2.pollJobs(build.Manager)
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:    jobID,
		Build: *build,
		Log:   []byte("bisect log"),
		Commits: []dashapi.Commit{
			{
				Hash:       "111111111111111111111111",
				Title:      "kernel: break build",
				Author:     "hacker@kernel.org",
				AuthorName: "Hacker Kernelov",
				CC:         []string{"reviewer1@kernel.org", "reviewer2@kernel.org"},
				Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
			{
				Hash:       "222222222222222222222222",
				Title:      "kernel: now add a bug to the broken build",
				Author:     "author@kernel.org",
				AuthorName: "Author Kernelov",
				CC:         []string{"reviewer3@kernel.org", "reviewer4@kernel.org"},
				Date:       time.Date(2001, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)
	_, dbCrash, _ := c.loadBug(extBugID)
	reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	reproCLink := externalLink(c.ctx, textReproC, dbCrash.ReproC)
	dbJob, dbBuild, dbJobCrash := c.loadJob(jobID)
	kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
	bisectLogLink := externalLink(c.ctx, textLog, dbJob.Log)
	crashLogLink := externalLink(c.ctx, textCrashLog, dbJobCrash.Log)

	{
		msg := c.pollEmailBug()
		// Not mailed to commit author/cc because !MailMaintainers.
		c.expectEQ(msg.To, []string{"test@syzkaller.com"})
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Bisection is inconclusive: the first bad commit could be any of:

111111111111 kernel: break build
222222222222 kernel: now add a bug to the broken build

bisection log:  %[2]v
start commit:   111111111111 kernel_commit_title1
git tree:       repo1 branch1
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
syz repro:      %[4]v
C reproducer:   %[5]v

For information about bisection process see: https://goo.gl/tpsmEJ#bisection
`, extBugID, bisectLogLink, kernelConfigLink, reproSyzLink, reproCLink))
	}

	// The next reporting must get bug report with bisection results.
	c.incomingEmail(msg.Sender, "#syz upstream")
	{
		msg := c.pollEmailBug()
		_, extBugID2, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		c.expectEQ(msg.To, []string{
			"bugs@syzkaller.com",
			"default@maintainers.com",
		})
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot found the following issue on:

HEAD commit:    111111111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[2]v
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
syz repro:      %[4]v
C reproducer:   %[5]v

Bisection is inconclusive: the first bad commit could be any of:

111111111111 kernel: break build
222222222222 kernel: now add a bug to the broken build

bisection log:  %[6]v

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
For information about bisection process see: https://goo.gl/tpsmEJ#bisection

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

If you want to overwrite report's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the report is a duplicate of another one, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup`,
			extBugID2, crashLogLink, kernelConfigLink, reproSyzLink, reproCLink, bisectLogLink))
	}
}

func TestUnreliableBisect(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	// Upload a crash that has only a syz repro.
	crash := testCrashWithRepro(build, 1)
	crash.ReproC = nil
	c.client2.ReportCrash(crash)
	_ = c.client2.pollEmailBug()

	pollResp := c.client2.pollJobs(build.Manager)
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:    jobID,
		Build: *build,
		Log:   []byte("bisect log"),
		Flags: dashapi.BisectResultRelease,
		Commits: []dashapi.Commit{
			{
				Hash:       "111111111111111111111111",
				Title:      "Linux 4.10",
				Author:     "abcd@kernel.org",
				AuthorName: "Abcd Efgh",
				CC:         []string{"reviewer1@kernel.org", "reviewer2@kernel.org"},
				Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	// The bisection result is unreliable - it shouldn't be reported.
	c.expectNoEmail()

	// Upload a crash with a C repro.
	crash2 := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash2)

	// Make sure it doesn't mention bisection and doesn't include the emails from it.
	msg := c.pollEmailBug()
	c.expectEQ(msg.To, []string{"test@syzkaller.com"})
	c.expectEQ(msg.Subject, crash.Title)
	c.expectTrue(strings.Contains(msg.Body, "syzbot has found a reproducer for the following issue"))
	c.expectTrue(!strings.Contains(msg.Body, "bisection"))
}

func TestBisectWrong(t *testing.T) {
	// Test bisection results with BisectResultMerge/BisectResultNoop flags set.
	// If any of these set, the result must not be reported separately,
	// as part of bug report during upstreamming, nor should affect CC list.
	c := NewCtx(t)
	defer c.Close()

	// Otherwise "Bug obsoleted" emails mix in at random times.
	c.setNoObsoletions()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	for i := 0; i < 6; i++ {
		var flags dashapi.JobDoneFlags
		switch i {
		case 0:
		case 1:
			flags = dashapi.BisectResultMerge
		case 2:
			flags = dashapi.BisectResultNoop
		case 3:
			flags = dashapi.BisectResultMerge | dashapi.BisectResultNoop
		case 4:
			flags = dashapi.BisectResultRelease
		case 5:
			flags = dashapi.BisectResultIgnore
		default:
			t.Fatalf("assign flags")
		}
		t.Logf("iteration %v: flags=%v", i, flags)

		crash := testCrashWithRepro(build, i)
		c.client2.ReportCrash(crash)
		c.client2.pollEmailBug()

		{
			pollResp := c.client2.pollJobs(build.Manager)
			done := &dashapi.JobDoneReq{
				ID:    pollResp.ID,
				Flags: flags,
				Build: *build,
				Log:   []byte("bisect log"),
				Commits: []dashapi.Commit{
					{
						Hash:       "111111111111111111111111",
						Title:      "kernel: break build",
						Author:     "hacker@kernel.org",
						AuthorName: "Hacker Kernelov",
						Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
					},
				},
			}
			done.Build.ID = pollResp.ID
			c.expectOK(c.client2.JobDone(done))
			if i == 0 {
				msg := c.pollEmailBug()
				c.expectTrue(strings.Contains(msg.Body, "syzbot has bisected this issue to:"))
			} else {
				c.expectNoEmail()
			}
		}
		{
			c.advanceTime(31 * 24 * time.Hour)
			pollResp := c.client2.pollJobs(build.Manager)
			done := &dashapi.JobDoneReq{
				ID:          pollResp.ID,
				Flags:       flags,
				Build:       *build,
				Log:         []byte("bisectfix log 4"),
				CrashTitle:  "bisectfix crash title 4",
				CrashLog:    []byte("bisectfix crash log 4"),
				CrashReport: []byte("bisectfix crash report 4"),
				Commits: []dashapi.Commit{
					{
						Hash:       "46e65cb4a0448942ec316b24d60446bbd5cc7827",
						Title:      "kernel: add a fix",
						Author:     "fixer@kernel.org",
						AuthorName: "Author Kernelov",
						Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
					},
				},
			}
			done.Build.ID = pollResp.ID
			c.expectOK(c.client2.JobDone(done))
			if i == 0 {
				msg := c.pollEmailBug()
				c.expectTrue(strings.Contains(msg.Body, "syzbot suspects this issue was fixed by commit:"))
			}
		}
		{
			// Auto-upstreamming.
			c.advanceTime(31 * 24 * time.Hour)
			msg := c.pollEmailBug()
			c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))
			msg = c.pollEmailBug()
			c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue on:"))
			if i == 0 {
				c.expectTrue(strings.Contains(msg.Body, "The issue was bisected to:"))
				c.expectEQ(msg.To, []string{
					"bugs@syzkaller.com",
					"default@maintainers.com",
					"hacker@kernel.org",
				})
			} else {
				c.expectTrue(!strings.Contains(msg.Body, "The issue was bisected to:"))
				c.expectEQ(msg.To, []string{
					"bugs@syzkaller.com",
					"default@maintainers.com",
				})
			}
		}
		c.expectNoEmail()
	}
}

func TestBisectCauseAncient(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	msg := c.client2.pollEmailBug()

	pollResp := c.client2.pollJobs(build.Manager)
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:          jobID,
		Build:       *build,
		Log:         []byte("bisect log"),
		CrashTitle:  "bisect crash title",
		CrashLog:    []byte("bisect crash log"),
		CrashReport: []byte("bisect crash report"),
	}
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)
	_, dbCrash, _ := c.loadBug(extBugID)
	reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
	reproCLink := externalLink(c.ctx, textReproC, dbCrash.ReproC)
	dbJob, dbBuild, dbJobCrash := c.loadJob(jobID)
	bisectCrashReportLink := externalLink(c.ctx, textCrashReport, dbJob.CrashReport)
	bisectCrashLogLink := externalLink(c.ctx, textCrashLog, dbJob.CrashLog)
	kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
	bisectLogLink := externalLink(c.ctx, textLog, dbJob.Log)
	crashLogLink := externalLink(c.ctx, textCrashLog, dbJobCrash.Log)

	{
		msg := c.pollEmailBug()
		// Not mailed to commit author/cc because !MailMaintainers.
		c.expectEQ(msg.To, []string{"test@syzkaller.com"})
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Bisection is inconclusive: the issue happens on the oldest tested release.

bisection log:  %[2]v
oldest commit:  111111111111 kernel_commit_title1
git tree:       repo1 branch1
final oops:     %[3]v
console output: %[4]v
kernel config:  %[5]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
syz repro:      %[6]v
C reproducer:   %[7]v

For information about bisection process see: https://goo.gl/tpsmEJ#bisection
`, extBugID, bisectLogLink, bisectCrashReportLink, bisectCrashLogLink,
			kernelConfigLink, reproSyzLink, reproCLink))
	}

	// The next reporting must get bug report with bisection results.
	c.incomingEmail(msg.Sender, "#syz upstream")
	{
		msg := c.pollEmailBug()
		_, extBugID2, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		c.expectEQ(msg.To, []string{
			"bugs@syzkaller.com",
			"default@maintainers.com",
		})
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot found the following issue on:

HEAD commit:    111111111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[2]v
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
syz repro:      %[4]v
C reproducer:   %[5]v

Bisection is inconclusive: the issue happens on the oldest tested release.

bisection log:  %[6]v
final oops:     %[7]v
console output: %[8]v

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1

---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
For information about bisection process see: https://goo.gl/tpsmEJ#bisection

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

If you want to overwrite report's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the report is a duplicate of another one, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup`,
			extBugID2, crashLogLink, kernelConfigLink, reproSyzLink, reproCLink,
			bisectLogLink, bisectCrashReportLink, bisectCrashLogLink))
	}
}

func TestBisectCauseExternal(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client.ReportCrash(crash)
	rep := c.client.pollBug()

	pollResp := c.client.pollJobs(build.Manager)
	c.expectNE(pollResp.ID, "")
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:    jobID,
		Build: *build,
		Log:   []byte("bisect log"),
		Commits: []dashapi.Commit{
			{
				Hash:       "111111111111111111111111",
				Title:      "kernel: break build",
				Author:     "hacker@kernel.org",
				AuthorName: "Hacker Kernelov",
				CC:         []string{"reviewer1@kernel.org", "reviewer2@kernel.org"},
				Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	}
	done.Build.ID = jobID
	c.expectOK(c.client.JobDone(done))

	resp, _ := c.client.ReportingPollBugs("test")
	c.expectEQ(len(resp.Reports), 1)
	// Still reported because we did not ack.
	bisect := c.client.pollBug()
	// pollBug acks, must not be reported after that.
	c.client.pollBugs(0)

	c.expectEQ(bisect.Type, dashapi.ReportBisectCause)
	c.expectEQ(bisect.Title, rep.Title)
}

func TestBisectFixExternal(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client.ReportCrash(crash)
	rep := c.client.pollBug()
	{
		// Cause bisection fails.
		pollResp := c.client.pollJobs(build.Manager)
		done := &dashapi.JobDoneReq{
			ID:    pollResp.ID,
			Log:   []byte("bisect log"),
			Error: []byte("bisect error"),
		}
		c.expectOK(c.client.JobDone(done))
	}
	c.advanceTime(31 * 24 * time.Hour)
	{
		// Fix bisection succeeds.
		pollResp := c.client.pollJobs(build.Manager)
		done := &dashapi.JobDoneReq{
			ID:          pollResp.ID,
			Build:       *build,
			Log:         []byte("bisectfix log"),
			CrashTitle:  "bisectfix crash title",
			CrashLog:    []byte("bisectfix crash log"),
			CrashReport: []byte("bisectfix crash report"),
			Commits: []dashapi.Commit{
				{
					Hash:       "46e65cb4a0448942ec316b24d60446bbd5cc7827",
					Title:      "kernel: add a fix",
					Author:     "fixer@kernel.org",
					AuthorName: "Author Kernelov",
					Date:       time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
				},
			},
		}
		done.Build.ID = pollResp.ID
		c.expectOK(c.client.JobDone(done))
		rep := c.client.pollBug()
		c.expectEQ(rep.Type, dashapi.ReportBisectFix)
	}
	{
		// At this point the bug should be marked as fixed by the commit
		// because the namespace has FixBisectionAutoClose set.
		dbBug, _, _ := c.loadBug(rep.ID)
		c.expectEQ(dbBug.Commits, []string{"kernel: add a fix"})
		c.expectEQ(dbBug.HeadReproLevel, ReproLevelNone)
	}
}

func TestBisectCauseReproSyz(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	crash.ReproC = nil
	c.client2.ReportCrash(crash)

	pollResp := c.client2.pollJobs(build.Manager)
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:         jobID,
		Build:      *build,
		Log:        []byte("bisect log"),
		CrashTitle: "bisect crash title",
		CrashLog:   []byte("bisect crash log"),
	}
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	crash.ReproC = []byte("int main")
	c.client2.ReportCrash(crash)

	msg := c.client2.pollEmailBug()
	if !strings.Contains(msg.Body, "syzbot found the following issue") {
		t.Fatalf("wrong email header:\n%v", msg.Body)
	}
	if !strings.Contains(msg.Body, "Bisection is inconclusive") {
		t.Fatalf("report does not contain bisection results:\n%v", msg.Body)
	}
}

func TestBisectCauseReproSyz2(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	crash.ReproC = nil
	c.client2.ReportCrash(crash)

	pollResp := c.client2.pollJobs(build.Manager)
	jobID := pollResp.ID
	done := &dashapi.JobDoneReq{
		ID:         jobID,
		Build:      *build,
		Log:        []byte("bisect log"),
		CrashTitle: "bisect crash title",
		CrashLog:   []byte("bisect crash log"),
	}
	done.Build.ID = jobID
	c.expectOK(c.client2.JobDone(done))

	msg := c.client2.pollEmailBug()
	if !strings.Contains(msg.Body, "syzbot found the following issue") {
		t.Fatalf("wrong email header:\n%v", msg.Body)
	}
	if !strings.Contains(msg.Body, "Bisection is inconclusive") {
		t.Fatalf("report does not contain bisection results:\n%v", msg.Body)
	}

	crash.ReproC = []byte("int main")
	c.client2.ReportCrash(crash)

	msg = c.client2.pollEmailBug()
	if !strings.Contains(msg.Body, "syzbot has found a reproducer for the following issue") {
		t.Fatalf("wrong email header:\n%v", msg.Body)
	}
	// Do we need bisection results in this email as well?
	// We already mailed them, so we could not mail them here.
	// But if we don't include bisection results, need to check that CC is correct
	// (includes bisection CC).
	if !strings.Contains(msg.Body, "Bisection is inconclusive") {
		t.Fatalf("report still contains bisection results:\n%v", msg.Body)
	}
}

// Test that bisection results show up on UI.
func TestBugBisectionResults(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	_, bugKey := c.loadSingleBug()

	addBisectCauseJob(c, build)
	addBisectFixJob(c, build)

	// Ensure expected results show up on web UI
	url := fmt.Sprintf("/bug?id=%v", bugKey.StringID())
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectTrue(bytes.Contains(content, []byte("Fix bisection: fixed by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a fix")))
}

// Test that bisection status shows up on main page.
func TestBugBisectionStatus(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report.
	build, _ := addBuildAndCrash(c)

	addBisectCauseJob(c, build)

	// Fetch bug, namespace details.
	var bugs []*Bug
	_, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
	c.expectEQ(err, nil)
	c.expectEQ(len(bugs), 1)
	url := fmt.Sprintf("/%v", bugs[0].Namespace)
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("done")))

	addBisectFixJob(c, build)

	content, err = c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("done")))
}

// Test that invalidated bisections are not shown in the UI and marked as invalid.
func TestBugBisectionInvalidation(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	// Receive the JobBisectCause and send cause information.
	addBisectCauseJob(c, build)

	// Ensure expected results show up on web UI
	bug, bugKey := c.loadSingleBug()
	job, jobKey := c.loadSingleJob()
	bugURL := fmt.Sprintf("/bug?id=%v", bugKey.StringID())
	content, err := c.GET(bugURL)
	c.expectEQ(err, nil)
	c.expectEQ(bug.BisectCause, BisectYes)
	c.expectTrue(bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectEQ(job.InvalidatedBy, "")

	// Mark bisection as invalid, but do not restart it.
	_, err = c.AuthGET(AccessAdmin, "/admin?action=invalidate_bisection&key="+jobKey.Encode())
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusFound)

	// The invalidated bisection should have vanished from the web UI
	job, _ = c.loadSingleJob()
	content, err = c.GET(bugURL)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(!bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectEQ(job.InvalidatedBy, "user@syzkaller.com")

	// Wait 30 days, no new cause bisection jobs should be created.
	c.advanceTime(24 * 30 * time.Hour)
	resp := c.client2.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{
		BisectCause: true,
	})
	c.expectEQ(resp.ID, "")

	// Invalidate the bisection once more (why not), but this time ask dashboard to redo it.
	_, err = c.AuthGET(AccessAdmin, "/admin?action=invalidate_bisection&key="+jobKey.Encode()+"&restart=1")
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusFound)
	bug, _ = c.loadSingleBug()
	c.expectEQ(bug.BisectCause, BisectNot)

	// The bisection should be started again.
	c.advanceTime(time.Hour)
	resp = c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
}

// Upload a build, a crash report and poll bug emails.
func addBuildAndCrash(c *Ctx) (*dashapi.Build, *dashapi.Crash) {
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	c.advanceTime(30 * 24 * time.Hour)
	msg := c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))
	msg = c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))

	return build, crash
}

// Poll a JobBisectCause and send cause information.
func addBisectCauseJob(c *Ctx, build *dashapi.Build) (*dashapi.JobPollResp, *dashapi.JobDoneReq, string) {
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectCause)
	jobID := resp.ID
	done := &dashapi.JobDoneReq{
		ID:          jobID,
		Build:       *build,
		Log:         []byte("bisectfix log 4"),
		CrashTitle:  "bisectfix crash title 4",
		CrashLog:    []byte("bisectfix crash log 4"),
		CrashReport: []byte("bisectfix crash report 4"),
		Commits: []dashapi.Commit{
			{
				Hash:       "36e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a bug",
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

	c.advanceTime(24 * time.Hour)
	msg := c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "syzbot has bisected this issue to:"))

	return resp, done, jobID
}

// Poll a JobBisectfix and send fix information.
func addBisectFixJob(c *Ctx, build *dashapi.Build) (*dashapi.JobPollResp, *dashapi.JobDoneReq, string) {
	resp := c.client2.pollJobs(build.Manager)
	c.client2.expectNE(resp.ID, "")
	c.client2.expectEQ(resp.Type, dashapi.JobBisectFix)
	jobID := resp.ID
	done := &dashapi.JobDoneReq{
		ID:          jobID,
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
	msg := c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "syzbot suspects this issue was fixed by commit:"))

	// Ensure we do not automatically close the bug.
	c.expectTrue(!c.config().Namespaces["test2"].FixBisectionAutoClose)
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)
	dbBug, _, _ := c.loadBug(extBugID)
	c.expectTrue(len(dbBug.Commits) == 0)
	return resp, done, jobID
}
