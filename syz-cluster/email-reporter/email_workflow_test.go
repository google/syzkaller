// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"github.com/stretchr/testify/assert"
)

func TestPollerIntegration(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, reporterClient, emailServer, _ := setupHandlerTest(t, ctx, env, testSeries)

	// Send a report to get a report ID.
	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)
	_ = emailServer.email() // Consume moderation email.

	err = reporterClient.ConfirmReport(ctx, report.ID)
	assert.NoError(t, err)

	const messageID = "<message-id>"
	_, err = reporterClient.RecordReply(ctx, &api.RecordReplyReq{
		MessageID: messageID,
		ReportID:  report.ID,
		Reporter:  api.LKMLReporter,
	})
	assert.NoError(t, err)

	// Emulate lore archive.
	loreArchive := lore.NewTestLoreArchive(t, t.TempDir())
	writeTo := make(chan *lore.PolledEmail, 16)
	emailCfg := emailclient.TestEmailConfig()
	emailCfg.LoreArchiveURL = loreArchive.Repo.Dir

	poller, err := MakeLorePoller(t.TempDir(), emailCfg, writeTo)
	assert.NoError(t, err)

	t.Logf("sending a reply")
	loreArchive.SaveMessage(t, `Date: Sun, 7 May 2017 19:54:00 -0700
Subject: Reply to the Report
Message-ID: <direct-reply>
In-Reply-To: `+messageID+`
From: Someone <a@syzbot.org>
Content-Type: text/plain
 
`)

	err = poller.Poll(ctx, writeTo)
	assert.NoError(t, err)

	polled := <-writeTo
	assert.Equal(t, messageID, polled.RootMessageID)

	err = handler.ProcessPolledEmail(ctx, polled)
	assert.NoError(t, err)

	// Verify it was recorded by checking if we can record it again as new.
	res, err := reporterClient.RecordReply(ctx, &api.RecordReplyReq{
		MessageID:     "<direct-reply>",
		RootMessageID: polled.RootMessageID,
		Reporter:      api.LKMLReporter,
	})
	assert.NoError(t, err)
	assert.False(t, res.New)

	t.Run("ignore-own-email", func(t *testing.T) {
		loreArchive.SaveMessage(t, `Date: Sun, 7 May 2017 19:54:00 -0700
Subject: Reply from Bot
Message-ID: <bot-reply>
In-Reply-To: `+messageID+`
From: Bot <bot@syzbot.com>
Content-Type: text/plain

#syz upstream
`)
		err = poller.Poll(ctx, writeTo)
		assert.NoError(t, err)

		polled := <-writeTo
		err = handler.ProcessPolledEmail(ctx, polled)
		assert.ErrorIs(t, err, ErrOwnEmail)

		// Verify no email was sent in reply (it should be ignored).
		assert.Nil(t, emailServer.email())
	})

	t.Run("indirect-reply", func(t *testing.T) {
		loreArchive.SaveMessage(t, `Date: Sun, 7 May 2017 19:55:00 -0700
Subject: Reply to the Reply
Message-ID: <indirect-reply>
In-Reply-To: <direct-reply>
From: Someone Else <b@syzkaller.com>
Content-Type: text/plain

`)
		err = poller.Poll(ctx, writeTo)
		assert.NoError(t, err)

		polled := <-writeTo
		assert.Equal(t, messageID, polled.RootMessageID)

		err = handler.ProcessPolledEmail(ctx, polled)
		assert.NoError(t, err)

		// Verify it was recorded.
		res, err := reporterClient.RecordReply(ctx, &api.RecordReplyReq{
			MessageID:     "<indirect-reply>",
			RootMessageID: polled.RootMessageID,
			Reporter:      api.LKMLReporter,
		})
		assert.NoError(t, err)
		assert.False(t, res.New)
	})

	t.Run("identify-by-email-context", func(t *testing.T) {
		loreArchive.SaveMessage(t, `Date: Sun, 7 May 2017 19:55:00 -0700
Subject: New thread
Message-ID: <new-thread>
In-Reply-To: <whatever>
From: Someone Else <b@syzbot.org>
Cc: <bot+ci_`+report.ID+`@syzbot.com>
Content-Type: text/plain

`)
		err = poller.Poll(ctx, writeTo)
		assert.NoError(t, err)

		polled := <-writeTo
		err = handler.ProcessPolledEmail(ctx, polled)
		assert.NoError(t, err)

		assert.Equal(t, []string{report.ID}, polled.Email.BugIDs)
	})

	t.Run("unknown-report", func(t *testing.T) {
		loreArchive.SaveMessage(t, `Date: Sun, 7 May 2017 19:56:00 -0700
Subject: Unrelated Message
Message-ID: <unrelated>
From: Someone Else <b@syzkaller.com>
Content-Type: text/plain

`)
		err = poller.Poll(ctx, writeTo)
		assert.NoError(t, err)

		polled := <-writeTo
		err = handler.ProcessPolledEmail(ctx, polled)
		assert.ErrorIs(t, err, ErrUnknownReport)
	})
}
