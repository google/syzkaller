// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"github.com/google/syzkaller/syz-cluster/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModerationReportFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer, _ := setupHandlerTest(t, ctx, env, testSeries)

	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail := emailServer.email()
	assert.NotNil(t, receivedEmail, "a moderation email must be sent")
	receivedEmail.Body = nil // for now don't validate the body
	testEmailConfig := emailclient.TestEmailConfig()
	assert.Equal(t, &emailclient.Email{
		To:      []string{testEmailConfig.ModerationList},
		Cc:      []string{testEmailConfig.ArchiveList},
		Subject: "[moderation/CI] Re: " + testSeries.Title,
		BugID:   report.ID,
		// Note that InReplyTo and Cc are nil.
	}, receivedEmail)

	// Emulate an "upstream" command.
	err = handler.IncomingEmail(ctx, &email.Email{
		BugIDs: []string{report.ID},
		Commands: []*email.SingleCommand{
			{
				Command: email.CmdUpstream,
			},
		},
	})
	assert.NoError(t, err)

	// The report must be sent upstream.
	report, err = handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail = emailServer.email()
	assert.NotNil(t, receivedEmail, "an email must be sent upstream")
	receivedEmail.Body = nil
	assert.Equal(t, &emailclient.Email{
		To:        testSeries.Cc,
		Cc:        append([]string{emailclient.TestEmailConfig().ArchiveList}, emailclient.TestEmailConfig().ReportCC...),
		Subject:   "[name] Re: " + testSeries.Title,
		InReplyTo: testSeries.ExtID,
		BugID:     report.ID,
	}, receivedEmail)
}

func TestReportInvalidationFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer, _ := setupHandlerTest(t, ctx, env, testSeries)

	report, err := handler.PollAndReport(ctx)
	require.NoError(t, err)

	receivedEmail := emailServer.email()
	require.NotNil(t, receivedEmail, "a moderation email must be sent")
	receivedEmail.Body = nil // for now don't validate the body

	// Emulate an "upstream" command.
	err = handler.IncomingEmail(ctx, &email.Email{
		BugIDs: []string{report.ID},
		Commands: []*email.SingleCommand{
			{
				Command: email.CmdInvalid,
			},
		},
	})
	require.NoError(t, err)

	// The report must be not sent upstream.
	report, err = handler.PollAndReport(ctx)
	require.NoError(t, err)
	assert.Nil(t, report)

	receivedEmail = emailServer.email()
	assert.Nil(t, receivedEmail, "an email must not be sent upstream")
}

func TestInvalidReply(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer, _ := setupHandlerTest(t, ctx, env, testSeries)

	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail := emailServer.email()
	assert.NotNil(t, receivedEmail, "a moderation email must be sent")
	receivedEmail.Body = nil

	t.Run("unrelated email", func(t *testing.T) {
		err = handler.IncomingEmail(ctx, &email.Email{
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdUpstream,
				},
			},
		})
		assert.ErrorIs(t, err, ErrUnknownReport)
		_, err = handler.PollAndReport(ctx)
		assert.NoError(t, err)
		// No email must be sent in reply.
		assert.Nil(t, emailServer.email())
	})

	t.Run("unsupported command", func(t *testing.T) {
		err := handler.IncomingEmail(ctx, &email.Email{
			Author:    "user@email.com",
			Subject:   "Command",
			BugIDs:    []string{report.ID},
			Cc:        []string{"a@a.com", "b@b.com"},
			MessageID: "user-reply-msg-id",
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdFix,
					Str:     "fix:",
				},
			},
			Body: `#syz fix: abcd`,
		})
		assert.NoError(t, err)
		reply := emailServer.email()
		assert.NotNil(t, reply)
		assert.Equal(t, &emailclient.Email{
			To:        []string{"user@email.com"},
			Cc:        []string{"a@a.com", "b@b.com"},
			Subject:   "Re: Command",
			InReplyTo: "user-reply-msg-id",
			Body: []byte(`> #syz fix: abcd

syzbot-ci does not support` + " `fix:` " + `command

`),
		}, reply)
	})

	t.Run("own email", func(t *testing.T) {
		err = handler.IncomingEmail(ctx, &email.Email{
			OwnEmail: true,
			BugIDs:   []string{report.ID},
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdUpstream,
				},
			},
		})
		assert.ErrorIs(t, err, ErrOwnEmail)
		_, err = handler.PollAndReport(ctx)
		assert.NoError(t, err)
		// No email must be sent in reply.
		assert.Nil(t, emailServer.email())
	})

	t.Run("forwarded email", func(t *testing.T) {
		err = handler.IncomingEmail(ctx, &email.Email{
			Subject:  email.ForwardedPrefix + "abcd",
			OwnEmail: true,
			BugIDs:   []string{report.ID},
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdUpstream,
				},
			},
		})
		assert.NoError(t, err)
		_, err = handler.PollAndReport(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, emailServer.email())
	})
}

func TestSyzTestFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer, _ := setupHandlerTest(t, ctx, env, testSeries)

	report, err := handler.PollAndReport(ctx)
	require.NoError(t, err)
	receivedEmail := emailServer.email()
	require.NotNil(t, receivedEmail, "a moderation email must be sent")

	err = handler.IncomingEmail(ctx, &email.Email{
		Author:    "user@email.com",
		BugIDs:    []string{report.ID},
		MessageID: "user-reply-msg-id",
		Cc:        []string{"test-cc@email.com", "other@email.com"},
		Patch:     "--- a/file\n+++ b/file\n@@ -1,1 +1,1 @@\n-a\n+b\n",
		Commands: []*email.SingleCommand{
			{
				Command: email.CmdTest,
				Str:     "test",
			},
		},
	})
	require.NoError(t, err)
	reply := emailServer.email()
	assert.Nil(t, reply, "syz test should be silent on success")

	repo := db.NewSessionRepository(env.Spanner)
	list, err := repo.ListWaiting(context.Background(), 2)
	require.NoError(t, err)
	require.Len(t, list, 1)
	controller.FakeJobSession(t, env, handler.apiClient, list[0].ID)

	generator := reporter.NewGenerator(env)
	err = generator.Process(ctx, 1)
	require.NoError(t, err)

	_, err = handler.PollAndReport(ctx)
	require.NoError(t, err)

	reportReply := emailServer.email()
	testEmailConfig := emailclient.TestEmailConfig()
	require.NotNil(t, reportReply, "an email must be sent with the test results")
	assert.Equal(t, "user-reply-msg-id", reportReply.InReplyTo)
	assert.Equal(t, []string{"user@email.com", "test-cc@email.com", "other@email.com"}, reportReply.To)
	assert.Equal(t, append([]string{testEmailConfig.ArchiveList}, testEmailConfig.ReportCC...), reportReply.Cc)
	assert.Contains(t, string(reportReply.Body), "passed")
	assert.Contains(t, string(reportReply.Body), "/session/"+list[0].ID)

	// Some error cases.
	t.Run("missing patch", func(t *testing.T) {
		err = handler.IncomingEmail(ctx, &email.Email{
			Author:    "user@email.com",
			Subject:   "Command",
			BugIDs:    []string{report.ID},
			MessageID: "user-reply-msg-id-2",
			Cc:        []string{"error-cc1@email.com"},
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdTest,
					Str:     "test",
				},
			},
		})
		require.NoError(t, err)
		reply = emailServer.email()
		require.NotNil(t, reply)
		assert.Contains(t, string(reply.Body), "Please attach the patch to act upon")
		assert.Equal(t, []string{"user@email.com"}, reply.To)
		assert.Equal(t, []string{"error-cc1@email.com"}, reply.Cc)
	})

	t.Run("with args", func(t *testing.T) {
		err = handler.IncomingEmail(ctx, &email.Email{
			Author:    "user@email.com",
			Subject:   "Command",
			BugIDs:    []string{report.ID},
			MessageID: "user-reply-msg-id-3",
			Cc:        []string{"error-cc2@email.com"},
			Commands: []*email.SingleCommand{
				{
					Command: email.CmdTest,
					Args:    "git://repo.git branch",
					Str:     "test:",
				},
			},
		})
		require.NoError(t, err)
		reply = emailServer.email()
		require.NotNil(t, reply)
		assert.Contains(t, string(reply.Body), "does not support `#syz test` with arguments.")
		assert.Equal(t, []string{"user@email.com"}, reply.To)
		assert.Equal(t, []string{"error-cc2@email.com"}, reply.Cc)
	})
}

func setupHandlerTest(t *testing.T, ctx context.Context, env *app.AppEnvironment,
	series *api.Series) (*Handler, *api.ReporterClient, *fakeSender, controller.EntityIDs) {
	client := controller.TestServer(t, env)
	ids := controller.FakeSeriesWithFindings(t, ctx, env, client, series)

	generator := reporter.NewGenerator(env)
	err := generator.Process(ctx, 1)
	assert.NoError(t, err)

	emailServer := makeFakeSender()
	reporterClient := reporter.TestServer(t, env)
	handler := &Handler{
		reporter:       api.LKMLReporter,
		reporterClient: reporterClient,
		apiClient:      client,
		emailConfig:    emailclient.TestEmailConfig(),
		sender:         emailServer.send,
	}

	return handler, reporterClient, emailServer, ids.EntityIDs
}

type fakeSender struct {
	ch chan *emailclient.Email
}

func makeFakeSender() *fakeSender {
	return &fakeSender{
		ch: make(chan *emailclient.Email, 16),
	}
}

func (f *fakeSender) send(ctx context.Context, e *emailclient.Email) (string, error) {
	f.ch <- e
	return "email-id", nil
}

func (f *fakeSender) email() *emailclient.Email {
	select {
	case e := <-f.ch:
		return e
	default:
		return nil
	}
}
