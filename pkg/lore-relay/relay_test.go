// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/email/sender"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSender struct {
	sent []*sender.Email
	id   int
}

func (m *mockSender) Send(ctx context.Context, email *sender.Email) (string, error) {
	m.sent = append(m.sent, email)
	m.id++
	return fmt.Sprintf("<mock@msgid-%d>", m.id), nil
}

func TestMainScenario(t *testing.T) {
	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	pollerCfg := lore.PollerConfig{
		RepoDir: t.TempDir(),
		URL:     loreArchive.Repo.Dir,
		Tracer:  &debugtracer.TestTracer{T: t},
	}

	poller, err := lore.NewPoller(pollerCfg)
	require.NoError(t, err)

	mockDash := &mockDashboard{
		pollResp: &dashapi.PollExternalReportResp{
			Result: &dashapi.ReportPollResult{
				ID: "job1",
				To: []string{"maintainer@email"},
				Cc: []string{"cc@email"},
				Patch: &dashapi.NewReportResult{
					Subject: "Fix bug",
					Body:    "Fix body",
					To:      []string{"intended_to@email"},
					Cc:      []string{"intended_cc@email"},
				},
			},
		},
	}
	mockSnd := &mockSender{}
	relay := NewRelay(&Config{
		LoreArchive: "archive@lore.com",
	}, mockDash, poller, mockSnd)

	// 1. Dashboard comes up with a patch.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"maintainer@email"}, mockSnd.sent[0].To)
	assert.Equal(t, []string{"cc@email", "archive@lore.com"}, mockSnd.sent[0].Cc)
	assert.Equal(t, "[PATCH RFC] Fix bug", mockSnd.sent[0].Subject)

	require.Len(t, mockDash.confirmed, 1)
	assert.Equal(t, "job1", mockDash.confirmed[0].ReportID)
	assert.Equal(t, "<mock@msgid-1>", mockDash.confirmed[0].PublishedExtID)

	// 2. User reply that's unrelated to it.
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

This looks interesting.
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockDash.commands, 0)

	// 3. #syz upstream to (2).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply2>
In-Reply-To: <reply1>

#syz upstream
`, now.Add(2*time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 4. Verify dashboard receives command and root id is good.
	assert.Equal(t, []*dashapi.SendExternalCommandReq{
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
	}, mockDash.commands)

	// 5. #syz reject to (2).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply3>
In-Reply-To: <reply1>

#syz reject
`, now.Add(3*time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 6. Verify dashboard receives command and root it is good.
	assert.Equal(t, []*dashapi.SendExternalCommandReq{
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply3>",
			Author:       "user@email",
			Reject: &dashapi.RejectCommand{
				Reason: "#syz reject\n",
			},
		},
	}, mockDash.commands)
}

func TestRestartScenario(t *testing.T) {
	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	createRelay := func(mockDash *mockDashboard) (*Relay, *lore.Poller) {
		pollerCfg := lore.PollerConfig{
			RepoDir: t.TempDir(),
			URL:     loreArchive.Repo.Dir,
			Tracer:  &debugtracer.TestTracer{T: t},
		}
		poller, err := lore.NewPoller(pollerCfg)
		require.NoError(t, err)
		mockSnd := &mockSender{}
		relay := NewRelay(&Config{}, mockDash, poller, mockSnd)
		return relay, poller
	}

	mockDash := &mockDashboard{
		pollResp: &dashapi.PollExternalReportResp{
			Result: &dashapi.ReportPollResult{
				ID: "job1",
				To: []string{"maintainer@email"},
				Patch: &dashapi.NewReportResult{
					Subject: "Fix bug",
					Body:    "Fix body",
				},
			},
		},
	}

	relay, _ := createRelay(mockDash)

	// 1. Dashboard comes up with a patch.
	err := relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	// 2. User reply that's unrelated to it.
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

This looks interesting.
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	t.Logf("restarting relay")
	relay, _ = createRelay(mockDash)

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)
	require.Len(t, mockDash.commands, 0)

	// 3. #syz upstream to (2).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply2>
In-Reply-To: <reply1>

#syz upstream
`, now.Add(2*time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 4. Verify that dashboard receives the command and root id is good.
	assert.Equal(t, []*dashapi.SendExternalCommandReq{
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
	}, mockDash.commands)

	t.Logf("restarting relay")
	relay, _ = createRelay(mockDash)

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []*dashapi.SendExternalCommandReq{
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
	}, mockDash.commands)

	// 5. #syz reject to (2).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH] Fix bug
Message-ID: <reply3>
In-Reply-To: <reply1>

#syz reject
`, now.Add(3*time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 6. Verify that dashboard receives the command and root it is good.
	assert.Equal(t, []*dashapi.SendExternalCommandReq{
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply2>",
			Author:       "user@email",
			Upstream:     &dashapi.UpstreamCommand{},
		},
		{
			Source:       "lore",
			RootExtID:    "<mock@msgid-1>",
			MessageExtID: "<reply3>",
			Author:       "user@email",
			Reject: &dashapi.RejectCommand{
				Reason: "#syz reject\n",
			},
		},
	}, mockDash.commands)
}

func TestErrorReply(t *testing.T) {
	loreArchive := lore.NewTestLoreArchive(t, t.TempDir())

	cfg := &Config{
		DashboardPollInterval: time.Hour,
		LorePollInterval:      time.Hour,
	}

	mockDash := &mockDashboard{
		cmdResp: &dashapi.SendExternalCommandResp{Error: "invalid command syntax"},
	}
	mockSnd := &mockSender{}

	lorePoller, err := lore.NewPoller(lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"own@email.com"},
	})
	require.NoError(t, err)
	relay := NewRelay(cfg, mockDash, lorePoller, mockSnd)

	now := time.Now()
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: [PATCH] Fix bug
Message-ID: <msg1>

#syz upstream
`, now)

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockDash.commands, 1)
	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"user@email"}, mockSnd.sent[0].To)
	assert.Equal(t, "Re: [PATCH] Fix bug", mockSnd.sent[0].Subject)
	assert.Equal(t, "<msg1>", mockSnd.sent[0].InReplyTo)
	expectedBody := "> #syz upstream\n\nCommand failed:\n\ninvalid command syntax\n\n"
	assert.Equal(t, expectedBody, string(mockSnd.sent[0].Body))
}

func TestMultipleCommandsReply(t *testing.T) {
	loreArchive := lore.NewTestLoreArchive(t, t.TempDir())
	cfg := &Config{LorePollInterval: time.Hour}
	mockDash := &mockDashboard{}
	mockSnd := &mockSender{}
	lorePoller, err := lore.NewPoller(lore.PollerConfig{
		RepoDir: t.TempDir(),
		URL:     loreArchive.Repo.Dir,
		Tracer:  &debugtracer.TestTracer{T: t},
	})
	require.NoError(t, err)
	relay := NewRelay(cfg, mockDash, lorePoller, mockSnd)

	loreArchive.SaveMessageAt(t, `From: user@email
Subject: [PATCH] Fix bug
Message-ID: <msg1>

#syz upstream
#syz reject
`, time.Now())

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"user@email"}, mockSnd.sent[0].To)
	expectedBody := "> #syz upstream\n> #syz reject\n\n" +
		"Command failed:\n\nmultiple commands in a single message are not supported\n\n"
	assert.Equal(t, expectedBody, string(mockSnd.sent[0].Body))
}

func TestBackoff(t *testing.T) {
	loreArchive := lore.NewTestLoreArchive(t, t.TempDir())
	cfg := &Config{
		LorePollInterval: time.Hour,
		Tracer:           &debugtracer.TestTracer{T: t},
	}

	mockDash := &mockDashboard{
		cmdErr: fmt.Errorf("transient error"),
	}
	mockSnd := &mockSender{}
	lorePoller, err := lore.NewPoller(lore.PollerConfig{
		RepoDir: t.TempDir(),
		URL:     loreArchive.Repo.Dir,
		Tracer:  &debugtracer.TestTracer{T: t},
	})
	require.NoError(t, err)
	relay := NewRelay(cfg, mockDash, lorePoller, mockSnd)
	relay.backoffs = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

	loreArchive.SaveMessageAt(t, `From: user@email
Subject: [PATCH] Fix bug
Message-ID: <msg1>

#syz upstream
`, time.Now())

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 1 initial failure + 1 success on retry = 2 calls!
	require.Len(t, mockDash.commands, 2)
}

func (m *mockDashboard) AIPollReport(req *dashapi.PollExternalReportReq) (*dashapi.PollExternalReportResp, error) {
	resp := m.pollResp
	m.pollResp = nil
	return resp, nil
}

func (m *mockDashboard) AIConfirmReport(req *dashapi.ConfirmPublishedReq) error {
	m.confirmed = append(m.confirmed, req)
	return nil
}

type mockDashboard struct {
	commands  []*dashapi.SendExternalCommandReq
	pollResp  *dashapi.PollExternalReportResp
	confirmed []*dashapi.ConfirmPublishedReq
	cmdResp   *dashapi.SendExternalCommandResp
	cmdErr    error
}

func (m *mockDashboard) AIReportCommand(req *dashapi.SendExternalCommandReq) (*dashapi.SendExternalCommandResp, error) {
	m.commands = append(m.commands, req)
	if m.cmdErr != nil {
		err := m.cmdErr
		m.cmdErr = nil // Use only once!
		return nil, err
	}
	if m.cmdResp != nil {
		return m.cmdResp, nil
	}
	return &dashapi.SendExternalCommandResp{}, nil
}
