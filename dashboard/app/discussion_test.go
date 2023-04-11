// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
)

func TestDiscussionAccess(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublic, keyPublic, true)

	build := testBuild(1)
	client.UploadBuild(build)

	// Bug at the first (AccesUser) stage of reporting.
	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	rep1 := client.pollBug()

	// Bug at the second (AccessPublic) stage.
	crash2 := testCrash(build, 2)
	client.ReportCrash(crash2)
	rep2user := client.pollBug()
	client.updateBug(rep2user.ID, dashapi.BugStatusUpstream, "")
	rep2 := client.pollBug()

	// Patch to both bugs.
	firstTime := timeNow(c.ctx)
	c.advanceTime(time.Hour)
	c.expectOK(client.SaveDiscussion(&dashapi.SaveDiscussionReq{
		Discussion: &dashapi.Discussion{
			ID:      "123",
			Source:  dashapi.DiscussionLore,
			Type:    dashapi.DiscussionPatch,
			Subject: "Patch for both bugs",
			BugIDs:  []string{rep1.ID, rep2.ID},
			Messages: []dashapi.DiscussionMessage{
				{
					ID:       "123",
					External: true,
					Time:     firstTime,
				},
			},
		},
	}))

	// Discussion about the second bug.
	secondTime := timeNow(c.ctx)
	c.advanceTime(time.Hour)
	c.expectOK(client.SaveDiscussion(&dashapi.SaveDiscussionReq{
		Discussion: &dashapi.Discussion{
			ID:      "456",
			Source:  dashapi.DiscussionLore,
			Type:    dashapi.DiscussionReport,
			Subject: "Second bug reported",
			BugIDs:  []string{rep2.ID},
			Messages: []dashapi.DiscussionMessage{
				{
					ID:       "456",
					External: false,
					Time:     secondTime,
				},
			},
		},
	}))

	firstBug, _, err := findBugByReportingID(c.ctx, rep1.ID)
	c.expectOK(err)

	// Verify discussion that spans only one bug.
	got, err := getBugDiscussionsUI(c.ctx, firstBug)
	c.expectOK(err)
	if diff := cmp.Diff([]*uiBugDiscussion{
		{
			Subject:  "Patch for both bugs",
			Link:     "https://lore.kernel.org/all/123/T/",
			Total:    1,
			External: 1,
			Last:     firstTime,
		},
	}, got); diff != "" {
		t.Fatal(diff)
	}

	secondBug, _, err := findBugByReportingID(c.ctx, rep2.ID)
	c.expectOK(err)

	// Verify that we also show discussions for several bugs.
	got, err = getBugDiscussionsUI(c.ctx, secondBug)
	c.expectOK(err)
	if diff := cmp.Diff([]*uiBugDiscussion{
		{
			Subject:  "Second bug reported",
			Link:     "https://lore.kernel.org/all/456/T/",
			Total:    1,
			External: 0,
			Last:     secondTime,
		},
		{
			Subject:  "Patch for both bugs",
			Link:     "https://lore.kernel.org/all/123/T/",
			Total:    1,
			External: 1,
			Last:     firstTime,
		},
	}, got); diff != "" {
		t.Fatal(diff)
	}

	// Verify the summary.
	summary := secondBug.discussionSummary()
	if diff := cmp.Diff(DiscussionSummary{
		AllMessages:      2,
		ExternalMessages: 1,
		LastMessage:      secondTime,
		LastPatchMessage: firstTime,
	}, summary); diff != "" {
		t.Fatal(diff)
	}
}

func TestEmailOwnDiscussions(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	msg := client.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)

	// Start a discussion.
	incoming1 := fmt.Sprintf(`Sender: syzkaller@googlegroups.com
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <1234>
Subject: Bug reported
From: %v
To: foo@bar.com, linux-kernel@vger.kernel.org
Content-Type: text/plain

Hello`, msg.Sender)
	_, err = c.POST("/_ah/mail/lore@email.com", incoming1)
	c.expectOK(err)

	bug, _, err := findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	zone := time.FixedZone("", -7*60*60)
	got, err := getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	if diff := cmp.Diff([]*uiBugDiscussion{
		{
			Subject:  "Bug reported",
			Link:     "https://lore.kernel.org/all/1234/T/",
			Total:    1,
			External: 0,
			Last:     time.Date(2017, time.August, 15, 14, 59, 0, 0, zone),
		},
	}, got); diff != "" {
		t.Fatal(diff)
	}

	// Emulate some user-reply to the discussion.
	incoming2 := fmt.Sprintf(`Sender: user@user.com
Date: Tue, 16 Aug 2017 14:59:00 -0700
Message-ID: <2345>
Subject: Re. Bug reported
From: user@user.com
In-Reply-To: <1234>
Cc: %v, linux-kernel@vger.kernel.org
Content-Type: text/plain

Hello`, msg.Sender)
	_, err = c.POST("/_ah/mail/lore@email.com", incoming2)
	c.expectOK(err)

	bug, _, err = findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	got, err = getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	if diff := cmp.Diff([]*uiBugDiscussion{
		{
			Subject:  "Bug reported",
			Link:     "https://lore.kernel.org/all/1234/T/",
			Total:    2,
			External: 1,
			Last:     time.Date(2017, time.August, 16, 14, 59, 0, 0, zone),
		},
	}, got); diff != "" {
		t.Fatal(diff)
	}
}

func TestEmailUnrelatedDiscussion(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	msg := client.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)

	// An email that's not sent to the target email address.
	incoming1 := fmt.Sprintf(`Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <1234>
Subject: Some discussion
In-Reply-To: <2345>
From: user@user.com
To: %v, lore@email.com
Content-Type: text/plain

Hello`, msg.Sender)
	_, err = c.POST("/_ah/mail/"+msg.Sender, incoming1)
	c.expectOK(err)

	bug, _, err := findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	// The discussion should go ignored.
	got, err := getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	if diff := cmp.Diff([]*uiBugDiscussion(nil), got); diff != "" {
		t.Fatal(diff)
	}
}

func TestEmailSubdiscussion(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	msg := client.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)

	incoming1 := fmt.Sprintf(`Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <2345>
Subject: Some discussion
In-Reply-To: <1234>
From: user@user.com
To: %v
Cc: lore@email.com
Content-Type: text/plain

Hello`, msg.Sender)
	_, err = c.POST("/_ah/mail/lore@email.com", incoming1)
	c.expectOK(err)

	bug, _, err := findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	// We have not seen the start of the discussion, but it should not go ignored.
	got, err := getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	client.expectEQ(len(got), 1)
	client.expectEQ(got[0].Link, "https://lore.kernel.org/all/2345/T/")
}

func TestEmailPatchWithLink(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	msg := client.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)

	incoming1 := fmt.Sprintf(`Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <2345>
Subject: [PATCH v3] A lot of fixes
From: user@user.com
To: lore@email.com
Content-Type: text/plain

Hello,

Link: https://testapp.appspot.com/bug?extid=%v
`, extBugID)
	_, err = c.POST("/_ah/mail/lore@email.com", incoming1)
	c.expectOK(err)

	bug, _, err := findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	// We have not seen the start of the discussion, but it should not go ignored.
	got, err := getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	client.expectEQ(len(got), 1)
	client.expectEQ(got[0].Link, "https://lore.kernel.org/all/2345/T/")
	client.expectEQ(got[0].Subject, "[PATCH v3] A lot of fixes")
}

func TestIgnoreBotReplies(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient

	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	client.ReportCrash(crash)
	msg := client.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	c.expectOK(err)

	incoming1 := fmt.Sprintf(`Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <2345>
Subject: Re: Patch testing request
From: %v
To: lore@email.com
In-Reply-To: <1234>
Content-Type: text/plain

Hello!
`, msg.Sender)
	_, err = c.POST("/_ah/mail/lore@email.com", incoming1)
	c.expectOK(err)

	bug, _, err := findBugByReportingID(c.ctx, extBugID)
	c.expectOK(err)

	// We have not seen the start of the discussion, but it should not go ignored.
	got, err := getBugDiscussionsUI(c.ctx, bug)
	c.expectOK(err)
	client.expectEQ(len(got), 0)
}
