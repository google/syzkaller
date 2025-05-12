// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/stretchr/testify/assert"
)

func TestEmailStream(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, reporterClient, _ := setupHandlerTest(t, env, ctx, testSeries)
	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)

	// Simulate our reply.
	err = reporterClient.ConfirmReport(ctx, report.ID)
	assert.NoError(t, err)
	const messageID = "<message-id>"
	err = reporterClient.UpdateReport(ctx, report.ID, &api.UpdateReportReq{
		MessageID: messageID,
	})
	assert.NoError(t, err)

	// Emulate the lore archive and set up the loop.
	loreArchive := newLoreArchive(t)
	writeTo := make(chan *email.Email, 16)
	stream := NewLKMLEmailStream(t.TempDir(), loreArchive.remoteRef(), reporterClient, writeTo)

	cancel := startStreamLoop(t, ctx, stream)

	t.Logf("sending a direct reply")
	loreArchive.saveMessage(t, `Date: Sun, 7 May 2017 19:54:00 -0700
Subject: Reply to the Report
Message-ID: <direct-reply>
In-Reply-To: `+messageID+`
From: Someone <a@syzbot.org>
Content-Type: text/plain

`)
	msg := <-writeTo
	assert.Equal(t, "<direct-reply>", msg.MessageID)
	assert.Equal(t, []string{report.ID}, msg.BugIDs)

	t.Logf("sending an indirect reply")
	loreArchive.saveMessage(t, `Date: Sun, 7 May 2017 19:55:00 -0700
Subject: Reply to the Reply
Message-ID: <indirect-reply>
In-Reply-To: <direct-reply>
From: Someone Else <b@syzbot.org>
Content-Type: text/plain

`)
	msg = <-writeTo
	assert.Equal(t, []string{report.ID}, msg.BugIDs)

	t.Logf("sending an unrelated message")
	loreArchive.saveMessage(t, `Date: Sun, 7 May 2017 19:56:00 -0700
Subject: Reply to the Reply
Message-ID: <another-reply>
From: Someone Else <b@syzbot.org>
Content-Type: text/plain

`)
	msg = <-writeTo
	assert.Len(t, msg.BugIDs, 0)

	t.Logf("stopping the loop")
	cancel()

	// Emulate service restart.
	stream = NewLKMLEmailStream(t.TempDir(), loreArchive.remoteRef(), reporterClient, writeTo)
	cancel = startStreamLoop(t, ctx, stream)
	defer cancel()
	// Only the unrelated message is expected to pop up.
	msg = <-writeTo
	assert.Equal(t, "<another-reply>", msg.MessageID)
}

func startStreamLoop(t *testing.T, ctx context.Context, stream *LKMLEmailStream) func() {
	done := make(chan struct{})
	loopCtx, cancel := context.WithCancel(ctx)
	go func() {
		err := stream.Loop(loopCtx, time.Second/10)
		assert.NoError(t, err)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

type loreArchive struct {
	repo *vcs.TestRepo
}

func newLoreArchive(t *testing.T) *loreArchive {
	return &loreArchive{
		repo: vcs.MakeTestRepo(t, t.TempDir()),
	}
}

func (a *loreArchive) remoteRef() string {
	return a.repo.Dir
}

func (a *loreArchive) saveMessage(t *testing.T, raw string) {
	err := os.WriteFile(filepath.Join(a.repo.Dir, "m"), []byte(raw), 0666)
	assert.NoError(t, err)
	a.repo.Git("add", "m")
	a.repo.CommitChange("some title")
}
