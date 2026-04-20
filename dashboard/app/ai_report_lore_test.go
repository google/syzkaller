// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/email/sender"
	lorerelay "github.com/google/syzkaller/pkg/lore-relay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAILoreIntegration(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

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

	mockSnd := &integrationMockSender{}

	relay := lorerelay.NewRelay(&lorerelay.Config{
		DocsLink:    "http://docs.link",
		LoreArchive: "archive@lore.com",
	}, c.globalClient, poller, mockSnd)

	// 1. Create a bug and AI job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Description",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
			"Recipients": []map[string]any{
				{"Name": "Maintainer", "Email": "maintainer@email.com", "To": true},
				{"Name": "Reviewer", "Email": "reviewer@email.com", "To": false},
			},
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"moderation@test.com"}, mockSnd.sent[0].To)
	assert.Equal(t, "[PATCH RFC] Test Description", mockSnd.sent[0].Subject)
	assert.Equal(t, []string{"archive@lore.com"}, mockSnd.sent[0].Cc)

	body := string(mockSnd.sent[0].Body)
	assert.Contains(t, body, "Final To: maintainer@email.com")
	assert.Contains(t, body, "Final Cc: reviewer@email.com")

	// 3. Approval (#syz upstream).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Description
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

#syz upstream
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 4. Poll Dashboard Again - should report to public.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 2) // Moderation email + Public email.
	assert.Equal(t, []string{"public@test.com", "maintainer@email.com"}, mockSnd.sent[1].To)
	assert.Equal(t, "[PATCH] Test Description", mockSnd.sent[1].Subject)
	assert.Equal(t, []string{"reviewer@email.com", "archive@lore.com"}, mockSnd.sent[1].Cc)

	bodyPublic := string(mockSnd.sent[1].Body)
	assert.NotContains(t, bodyPublic, "Final To:")

	// 5. Duplicate Approval (#syz upstream) - should fail because already upstreamed.
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Description
Message-ID: <reply2>
In-Reply-To: <mock@msgid-2>

#syz upstream
`, now.Add(time.Minute*2))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 3)
	assert.Equal(t, []string{"user@email"}, mockSnd.sent[2].To)
	expectedBody := "> #syz upstream\n\nCommand failed:\n\nno valid next stage found, all stages reported\n\n"
	assert.Equal(t, expectedBody, string(mockSnd.sent[2].Body))

	// Poll Lore again - nothing new should be found.
	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// Poll Dashboard again - still nothing.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 3)
}

func TestAILoreIntegrationReject(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

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

	mockSnd := &integrationMockSender{}

	relay := lorerelay.NewRelay(&lorerelay.Config{
		DocsLink:    "http://docs.link",
		LoreArchive: "archive@lore.com",
	}, c.globalClient, poller, mockSnd)

	// 1. Create a bug and AI job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Description",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"moderation@test.com"}, mockSnd.sent[0].To)
	assert.Equal(t, "[PATCH RFC] Test Description", mockSnd.sent[0].Subject)
	assert.Equal(t, []string{"archive@lore.com"}, mockSnd.sent[0].Cc)

	// 3. Reject (#syz reject).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Description
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

#syz reject
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 4. Poll Dashboard Again - should NOT report anywhere!
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
}

func TestAILoreUnknownMessageID(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	loreArchive := lore.NewTestLoreArchive(t, t.TempDir())

	cfg := &lorerelay.Config{
		DashboardPollInterval: time.Hour,
		LorePollInterval:      time.Hour,
	}

	mockSnd := &integrationMockSender{}
	lorePoller, err := lore.NewPoller(lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"own@email.com"},
	})
	require.NoError(t, err)
	relay := lorerelay.NewRelay(cfg, c.globalClient, lorePoller, mockSnd)

	now := time.Now()
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Description
Message-ID: <reply_err>
In-Reply-To: <non-existent-msg-id>

#syz upstream
`, now)

	// We should stay silent.
	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 0)
}

func TestAILoreIntegrationComment(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
		},
	})

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

	mockSnd := &integrationMockSender{}

	relay := lorerelay.NewRelay(&lorerelay.Config{
		DocsLink:    "http://docs.link",
		LoreArchive: "archive@lore.com",
	}, c.globalClient, poller, mockSnd)

	// 1. Create a bug and AI job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Description",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 1)

	// 3. Send a plain comment.
	loreArchive.SaveMessageAt(t, `From: reviewer@email
Subject: Re: [PATCH RFC] Test Description
Message-ID: <comment1>
In-Reply-To: <mock@msgid-1>

This is just a normal review comment with some context.
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// Verify that NO error reply was sent, meaning sent length is still exactly 1!
	require.Len(t, mockSnd.sent, 1)

	reportings, err := loadJobReportingsWithComments(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)
	require.Len(t, reportings[0].Comments, 1)
	assert.Equal(t, "reviewer@email", reportings[0].Comments[0].Author)
	assert.Contains(t, reportings[0].Comments[0].BodyURI, "This is just a normal review comment with some context.")
}

type integrationMockSender struct {
	sent []*sender.Email
}

func (m *integrationMockSender) Send(ctx context.Context, email *sender.Email) (string, error) {
	m.sent = append(m.sent, email)
	return fmt.Sprintf("<mock@msgid-%d>", len(m.sent)), nil
}
