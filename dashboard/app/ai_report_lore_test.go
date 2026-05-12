// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
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
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	pollerCfg := lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"syzbot@testapp.appspotmail.com"},
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

	err = c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: jobID,
		Span:  &trajectory.Span{Seq: 1, Type: trajectory.SpanAgent, Name: "patch-generator", Model: "gemini-3.1-pro-preview"},
	})
	require.NoError(t, err)
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
			"Fixes": map[string]any{
				"Hash":  "123456789012",
				"Title": "original bug",
			},
			"Recipients": []map[string]any{
				{"Name": "Maintainer", "Email": "maintainer@email.com", "To": true},
				{"Name": "Reviewer", "Email": "reviewer@email.com", "To": false},
			},
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"moderation@test.com"}, mockSnd.sent[0].To)
	assert.Equal(t, "[PATCH RFC] Test Subject", mockSnd.sent[0].Subject)
	assert.Equal(t, []string{"archive@lore.com"}, mockSnd.sent[0].Cc)

	body := string(mockSnd.sent[0].Body)
	assert.Contains(t, body, "Fixes: 123456789012 (\"original bug\")")
	assert.Contains(t, body, "Assisted-by: Gemini:gemini-3.1-pro-preview")
	assert.Contains(t, body, "Link: "+appURL(c.ctx)+"/bug?extid="+extID)
	assert.Contains(t, body, "Link: "+appURL(c.ctx)+"/ai_job?id="+jobID)
	assert.Contains(t, body, "To: <maintainer@email.com>")
	assert.Contains(t, body, "Cc: <reviewer@email.com>")
	// 3. Approval (#syz upstream).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Subject
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

#syz upstream
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// 4. Poll Dashboard Again - should report to public.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 2) // Moderation email + Public email.
	assert.Equal(t, []string{"public@test.com", "maintainer@email.com"}, mockSnd.sent[1].To)
	assert.Equal(t, "[PATCH] Test Subject", mockSnd.sent[1].Subject)
	assert.Equal(t, []string{"archive@lore.com", "reviewer@email.com"}, mockSnd.sent[1].Cc)

	bodyPublic := string(mockSnd.sent[1].Body)
	assert.NotContains(t, bodyPublic, "Final To:")

	// 5. Duplicate Approval (#syz upstream) - should fail because already upstreamed.
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Subject
Message-ID: <reply2>
In-Reply-To: <mock@msgid-2>

#syz upstream
`, now.Add(time.Minute*2))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 3)
	assert.Equal(t, []string{"user@email"}, mockSnd.sent[2].To)
	expectedBody := "> #syz upstream\n\nCommand failed:\n\nno valid next stage found, all stages reported\n\n"
	assert.Equal(t, expectedBody, string(mockSnd.sent[2].Body))

	// Poll Lore again - nothing new should be found.
	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// Poll Dashboard again - still nothing.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 3)
}

func TestAILoreIntegrationReject(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	pollerCfg := lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"syzbot@testapp.appspotmail.com"},
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
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 1)
	assert.Equal(t, []string{"moderation@test.com"}, mockSnd.sent[0].To)
	assert.Equal(t, "[PATCH RFC] Test Subject", mockSnd.sent[0].Subject)
	assert.Equal(t, []string{"archive@lore.com"}, mockSnd.sent[0].Cc)

	// 3. Reject (#syz reject).
	loreArchive.SaveMessageAt(t, `From: user@email
Subject: Re: [PATCH RFC] Test Subject
Message-ID: <reply1>
In-Reply-To: <mock@msgid-1>

#syz reject
`, now.Add(time.Minute))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// 4. Poll Dashboard Again - should NOT report anywhere!
	err = relay.PollDashboardOnce(t.Context())
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
Subject: Re: [PATCH RFC] Test Subject
Message-ID: <reply_err>
In-Reply-To: <non-existent-msg-id>

#syz upstream
`, now)

	// We should stay silent.
	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 0)
}

func TestAILoreIntegrationComment(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	pollerCfg := lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"syzbot@testapp.appspotmail.com"},
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
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
			"Fixes": map[string]any{
				"Hash":  "123456789012",
				"Title": "original bug",
			},
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 1)

	// 3. Send a plain comment.
	loreArchive.SaveMessageAt(t, "From: reviewer@email.com\n"+
		"Subject: Re: [PATCH RFC] Test Subject\n"+
		"Message-ID: <comment1>\n"+
		"In-Reply-To: <mock@msgid-1>\n\n"+
		"This is just a normal review comment with some context.\n", now.Add(time.Minute))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// Verify that NO error reply was sent, meaning sent length is still exactly 1!
	require.Len(t, mockSnd.sent, 1)

	// 3.5. Duplicate comment (e.g. from another list) should be ignored without 500 error.
	loreArchive.SaveMessageAt(t, "From: reviewer@email.com\n"+
		"Subject: Re: [PATCH RFC] Test Subject\n"+
		"Message-ID: <comment1>\n"+
		"In-Reply-To: <mock@msgid-1>\n\n"+
		"This is just a normal review comment with some context.\n", now.Add(time.Minute*2))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// 4. Send a reply from the bot itself.
	loreArchive.SaveMessageAt(t, "From: syzbot@testapp.appspotmail.com\n"+
		"Subject: Re: [PATCH RFC] Test Subject\n"+
		"Message-ID: <bot-reply>\n"+
		"In-Reply-To: <comment1>\n\n"+
		"This is a generated bot reply.\n", now.Add(time.Minute*2))
	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// Check if both comments were picked up properly and marked OwnEmail correctly.
	reportings, err := loadJobReportingsWithComments(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)
	require.Len(t, reportings[0].Comments, 2)

	// In tests, both the comment and the reply might be processed in the same lore-relay poll
	// cycle. Since the dashboard uses TimeNow() for the comment's CreatedAt timestamp rather
	// than the email's Date header, both comments may end up with the exact same timestamp.
	// This makes their order returned by Spanner non-deterministic, so we extract them by type.
	var userComment, botComment *aidb.JobComment
	for _, c := range reportings[0].Comments {
		if c.OwnEmail {
			botComment = c
		} else {
			userComment = c
		}
	}
	require.NotNil(t, userComment)
	require.NotNil(t, botComment)

	assert.Equal(t, "reviewer@email.com", userComment.Author)
	assert.Contains(t, userComment.BodyURI,
		"This is just a normal review comment with some context.")
	assert.False(t, userComment.OwnEmail)

	assert.Equal(t, "syzbot@testapp.appspotmail.com", botComment.Author)
	assert.Contains(t, botComment.BodyURI, "This is a generated bot reply.")
	assert.True(t, botComment.OwnEmail)
	// Should be automatically processed to avoid loops.
	assert.True(t, botComment.Processed)

	// 5. Complete the iteration job to verify CC behavior on replies and Fixes passing.
	// Advance time to pass the debounce logic so the iteration job gets created.
	c.advanceTime(31 * time.Minute)

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)

	// Verify that the original fixes hash was passed down.
	baseFixesMap := resp.Args["BaseFixes"].(map[string]any)
	require.Equal(t, "123456789012", baseFixesMap["Hash"])

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Replies": []map[string]any{
				{"ReplyTo": "<comment1>", "Text": "I will fix it."},
			},
		},
	})
	require.NoError(t, err)

	// 6. Poll Dashboard again - lore-relay should send the aggregated reply.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 2)
	// The original author should be merged directly into the To list.
	assert.Equal(t, []string{"moderation@test.com", "reviewer@email.com"}, mockSnd.sent[1].To)
	// And they should be completely subtracted from the CC list.
	assert.Equal(t, []string{"archive@lore.com"}, mockSnd.sent[1].Cc)
	assert.Equal(t, "Aggregated Comment Reply", mockSnd.sent[1].Subject)
	assert.Equal(t, "<comment1>", mockSnd.sent[1].InReplyTo)
}

type integrationMockSender struct {
	sent []*sender.Email
}

func (m *integrationMockSender) Send(ctx context.Context, email *sender.Email) (string, error) {
	m.sent = append(m.sent, email)
	return fmt.Sprintf("<mock@msgid-%d>", len(m.sent)), nil
}

func TestAILoreIteration(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	repoDir := t.TempDir()
	loreArchive := lore.NewTestLoreArchive(t, repoDir)

	now := time.Now()

	pollerCfg := lore.PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		Tracer:    &debugtracer.TestTracer{T: t},
		OwnEmails: []string{"syzbot@testapp.appspotmail.com"},
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
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
			"Fixes": map[string]any{
				"Hash":  "123456789012",
				"Title": "original bug",
			},
		},
	})
	require.NoError(t, err)

	// 2. Poll Dashboard - should report to moderation.
	err = relay.PollDashboardOnce(t.Context())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 1)

	// 3. Send a plain comment.
	loreArchive.SaveMessageAt(t, "From: reviewer@email.com\n"+
		"Subject: Re: [PATCH RFC] Test Subject\n"+
		"Message-ID: <comment1>\n"+
		"In-Reply-To: <mock@msgid-1>\n\n"+
		"This is just a normal review comment with some context.\n", now.Add(time.Minute))

	err = relay.PollLoreOnce(t.Context())
	require.NoError(t, err)

	// 4. Send a reply from the bot itself.
	loreArchive.SaveMessageAt(t, "From: syzbot@testapp.appspotmail.com\n"+
		"Subject: Re: [PATCH RFC] Test Subject\n"+
		"Message-ID: <bot-reply>\n"+
		"In-Reply-To: <comment1>\n\n"+
		"This is a generated bot reply.\n", now.Add(time.Minute*2))
	err = relay.PollLoreOnce(context.Background())
	require.NoError(t, err)

	// 5. Complete the iteration job to verify CC behavior on replies and Fixes passing.
	// Advance time to pass the debounce logic so the iteration job gets created.
	c.advanceTime(31 * time.Minute)

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)

	// Verify that the original fixes hash was passed down.
	baseFixesMap := resp.Args["BaseFixes"].(map[string]any)
	require.Equal(t, "123456789012", baseFixesMap["Hash"])

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff v2",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
			"Fixes": map[string]any{
				"Hash":  "abcdefabcdef",
				"Title": "introduce a bug",
			},
		},
	})
	require.NoError(t, err)

	// 6. Poll Dashboard again - lore-relay should send patch v2.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)

	require.Len(t, mockSnd.sent, 2)
	assert.Equal(t, "[PATCH v2] Test Subject", mockSnd.sent[1].Subject)
	body := string(mockSnd.sent[1].Body)
	assert.NotContains(t, body, "Test Subject")
	assert.Contains(t, body, "Fixes: abcdefabcdef (\"introduce a bug\")")

	// 7. But nothing else.
	err = relay.PollDashboardOnce(context.Background())
	require.NoError(t, err)
	require.Len(t, mockSnd.sent, 2)
}
