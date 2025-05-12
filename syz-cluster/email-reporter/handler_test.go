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
	"github.com/google/syzkaller/syz-cluster/pkg/reporter"
	"github.com/stretchr/testify/assert"
)

func TestModerationReportFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer := setupHandlerTest(t, env, ctx, testSeries)

	report, err := handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail := emailServer.email()
	assert.NotNil(t, receivedEmail, "a moderation email must be sent")
	receivedEmail.Body = nil // for now don't validate the body
	assert.Equal(t, &EmailToSend{
		To:      []string{testEmailConfig.ModerationList},
		Subject: "Re: " + testSeries.Title,
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
	_, err = handler.PollAndReport(ctx)
	assert.NoError(t, err)

	receivedEmail = emailServer.email()
	assert.NotNil(t, receivedEmail, "an email must be sent upstream")
	receivedEmail.Body = nil
	assert.Equal(t, &EmailToSend{
		To:        testSeries.Cc,
		Cc:        []string{testEmailConfig.ArchiveList},
		Subject:   "Re: " + testSeries.Title,
		InReplyTo: testSeries.ExtID,
	}, receivedEmail)
}

func TestInvalidReply(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	testSeries := controller.DummySeries()
	handler, _, emailServer := setupHandlerTest(t, env, ctx, testSeries)

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
		assert.Equal(t, &EmailToSend{
			To:        []string{"user@email.com"},
			Cc:        []string{"a@a.com", "b@b.com"},
			Subject:   "Re: Command",
			InReplyTo: "user-reply-msg-id",
			Body: []byte(`> #syz fix: abcd

Unknown command

`),
		}, reply)
	})
}

func setupHandlerTest(t *testing.T, env *app.AppEnvironment, ctx context.Context,
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
	ch chan *EmailToSend
}

func makeFakeSender() *fakeSender {
	return &fakeSender{
		ch: make(chan *EmailToSend, 16),
	}
}

func (f *fakeSender) send(ctx context.Context, e *EmailToSend) (string, error) {
	f.ch <- e
	return "email-id", nil
}

func (f *fakeSender) email() *EmailToSend {
	select {
	case e := <-f.ch:
		return e
	default:
		return nil
	}
}

var testEmailConfig = &app.EmailConfig{
	Name:           "name",
	DocsLink:       "docs",
	Sender:         "a@b.com",
	ModerationList: "moderation@list.com",
	ArchiveList:    "archive@list.com",
}
