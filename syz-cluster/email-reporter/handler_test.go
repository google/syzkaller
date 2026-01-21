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
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"github.com/google/syzkaller/syz-cluster/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testEmailConfig = emailclient.TestEmailConfig()

func TestModerationReportFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer := setupHandlerTest(t, ctx, env, testSeries)

	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail := emailServer.email()
	assert.NotNil(t, receivedEmail, "a moderation email must be sent")
	receivedEmail.Body = nil // for now don't validate the body
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
		Cc:        append([]string{testEmailConfig.ArchiveList}, testEmailConfig.ReportCC...),
		Subject:   "[name] Re: " + testSeries.Title,
		InReplyTo: testSeries.ExtID,
		BugID:     report.ID,
	}, receivedEmail)
}

func TestReportInvalidationFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer := setupHandlerTest(t, ctx, env, testSeries)

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
	handler, _, emailServer := setupHandlerTest(t, ctx, env, testSeries)

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
		assert.NoError(t, err)
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

Unknown command

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
		assert.NoError(t, err)
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

func setupHandlerTest(t *testing.T, ctx context.Context, env *app.AppEnvironment,
	series *api.Series) (*Handler, *api.ReporterClient, *fakeSender) {
	client := controller.TestServer(t, env)
	controller.FakeSeriesWithFindings(t, ctx, env, client, series)

	generator := reporter.NewGenerator(env)
	err := generator.Process(ctx, 1)
	assert.NoError(t, err)

	emailServer := makeFakeSender()
	reporterClient := reporter.TestServer(t, env)
	handler := &Handler{
		reporter:    api.LKMLReporter,
		apiClient:   reporterClient,
		emailConfig: testEmailConfig,
		sender:      emailServer.send,
	}
	return handler, reporterClient, emailServer
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
