// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestClientSecretOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "secr1t", "")
	if err != nil || got != "" {
		t.Errorf("unexpected error %v %v", got, err)
	}
}

func TestClientOauthOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "OauthSubject:public",
		},
	}, "user", "", "OauthSubject:public")
	if err != nil || got != "" {
		t.Errorf("unexpected error %v %v", got, err)
	}
}

func TestClientSecretFail(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "wrong", "")
	if err != ErrAccess || got != "" {
		t.Errorf("unexpected error %v %v", got, err)
	}
}

func TestClientSecretMissing(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{},
	}, "user", "ignored", "")
	if err != ErrAccess || got != "" {
		t.Errorf("unexpected error %v %v", got, err)
	}
}

func TestClientNamespaceOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Namespaces: map[string]*Config{
			"ns1": {
				Clients: map[string]string{
					"user": "secr1t",
				},
			},
		},
	}, "user", "secr1t", "")
	if err != nil || got != "ns1" {
		t.Errorf("unexpected error %v %v", got, err)
	}
}

func TestEmergentlyStoppedEmail(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)

	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessAdmin, "/admin?action=emergency_stop")
	c.expectOK(err)

	// There should be no email.
	c.advanceTime(time.Hour)
	c.expectNoEmail()
}

func TestEmergentlyStoppedReproEmail(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	c.pollEmailBug()

	crash2 := testCrash(build, 1)
	crash2.ReproOpts = []byte("repro opts")
	crash2.ReproSyz = []byte("getpid()")
	client.ReportCrash(crash2)

	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessAdmin, "/admin?action=emergency_stop")
	c.expectOK(err)

	// There should be no email.
	c.advanceTime(time.Hour)
	c.expectNoEmail()
}

func TestEmergentlyStoppedExternalReport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)

	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessAdmin, "/admin?action=emergency_stop")
	c.expectOK(err)

	// There should be no email.
	c.advanceTime(time.Hour)
	client.pollBugs(0)
}

func TestEmergentlyStoppedEmailJob(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("getpid()")
	client.ReportCrash(crash)
	sender := c.pollEmailBug().Sender
	c.incomingEmail(sender, "#syz upstream\n")
	sender = c.pollEmailBug().Sender

	// Send a patch testing request.
	c.advanceTime(time.Hour)
	c.incomingEmail(sender, syzTestGitBranchSamplePatch,
		EmailOptMessageID(1), EmailOptFrom("test@requester.com"),
		EmailOptCC([]string{"somebody@else.com", "test@syzkaller.com"}))
	c.expectNoEmail()

	// Emulate a finished job.
	pollResp := client.pollJobs(build.Manager)
	c.expectEQ(pollResp.Type, dashapi.JobTestPatch)

	c.advanceTime(time.Hour)
	jobDoneReq := &dashapi.JobDoneReq{
		ID:          pollResp.ID,
		Build:       *build,
		CrashTitle:  "test crash title",
		CrashLog:    []byte("test crash log"),
		CrashReport: []byte("test crash report"),
	}
	client.JobDone(jobDoneReq)

	// Now we emergently stop syzbot.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessAdmin, "/admin?action=emergency_stop")
	c.expectOK(err)

	// There should be no email.
	c.advanceTime(time.Hour)
	c.expectNoEmail()
}

func TestEmergentlyStoppedCrashReport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	// Now we emergently stop syzbot.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessAdmin, "/admin?action=emergency_stop")
	c.expectOK(err)

	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("getpid()")
	client.ReportCrash(crash)

	listResp, err := client.BugList()
	c.expectOK(err)
	c.expectEQ(len(listResp.List), 0)
}

func TestUpdateReportingPriority(t *testing.T) {
	bug := &Bug{
		Namespace: testConfig.DefaultNamespace,
		Title:     "bug",
	}
	build := Build{
		Namespace:    testConfig.DefaultNamespace,
		KernelRepo:   "git://syzkaller.org",
		KernelBranch: "branch10",
	}

	crashes := []*Crash{
		// This group of crashes should have the same priority.
		// Revoked and no repro.
		{
			BuildID:        "0",
			ReproIsRevoked: true,
		},
		// Non-revoked and no repro.
		{
			BuildID: "1",
		},
		// Revoked but has syz repro.
		{
			BuildID:        "2",
			ReproIsRevoked: true,
			ReproSyz:       1,
		},
		// Revoked but has C repro.
		{
			BuildID:        "3",
			ReproIsRevoked: true,
			ReproC:         1,
		},

		// This group of crashes should have the same priority.
		// Non-revoked and no repro but title matches with bug.
		{
			BuildID: "4",
			Title:   bug.Title,
		},
		// Revoked and has C repro and title matches with bug.
		{
			BuildID:        "5",
			ReproC:         1,
			Title:          bug.Title,
			ReproIsRevoked: true,
		},

		// Non-revoked and has syz repro.
		{
			BuildID:  "6",
			ReproSyz: 1,
		},
		// Non-revoked and has C repro.
		{
			BuildID: "7",
			ReproC:  1,
		},
		// Non-revoked and has C repro and title matches with bug.
		{
			BuildID: "8",
			ReproC:  1,
			Title:   bug.Title,
		},
		// Last. Non-revoked, has C repro, title matches with bug and arch is AMD64.
		{
			BuildID: "9",
			ReproC:  1,
			Title:   bug.Title,
		},
	}

	ctx := context.Background()
	for i, crash := range crashes {
		crash.Manager = "special-obsoleting"
		if i == len(crashes)-1 {
			build.Arch = targets.AMD64
		}
		crash.UpdateReportingPriority(ctx, &build, bug)
	}

	assert.True(t, sort.SliceIsSorted(crashes, func(i, j int) bool {
		return crashes[i].BuildID < crashes[j].BuildID
	}))

	var prios []int64
	for _, crash := range crashes {
		prios = append(prios, crash.ReportLen)
	}

	// "0-3", "4-5" have the same priority (repro revoked as no repro).
	assert.Equal(t, len(slices.Compact(prios)), len(prios)-4)
}
