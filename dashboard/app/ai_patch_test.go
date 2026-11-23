// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/stretchr/testify/require"
)

func TestAIPatchSync(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig("ains", &AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	// No patch while the job is running.
	extID, jobID := c.setupAIPatchJob(t)
	want := BugAIPatch{JobID: jobID, State: AIPatchPending}
	require.Equal(t, want, c.syncAIPatch(extID))

	// The patch is generated, but not reported yet.
	c.finishAIPatchJob(t, jobID, nil)
	want.State = AIPatchCandidate
	require.Equal(t, want, c.syncAIPatch(extID))

	c.advanceTime(time.Hour)
	c.pollAndConfirmReport(t, "lore", "<v1>")
	want.Posted = c.mockedTime
	want.Link = lore.LinkToThread("<v1>")
	require.Equal(t, want, c.syncAIPatch(extID))

	// Our own emails don't mean that somebody is reviewing the patch.
	c.advanceTime(time.Hour)
	c.commentOnAIPatch("<v1>", "<own-comment>", true)
	require.Equal(t, want, c.syncAIPatch(extID))
	c.commentOnAIPatch("<v1>", "<comment>", false)
	want.LastComment = c.mockedTime
	require.Equal(t, want, c.syncAIPatch(extID))

	c.holdAIPatch("<v1>", "<hold>", true)
	want.Held = true
	require.Equal(t, want, c.syncAIPatch(extID))

	// A new version continues the review of the same patch.
	c.advanceTime(time.Hour)
	iteration := c.pollAIWorkflow(t, ai.WorkflowPatchIteration)
	require.NotEmpty(t, iteration.ID)
	c.finishAIPatchJob(t, iteration.ID, nil)
	c.pollAndConfirmReport(t, "lore", "<v2>")
	want.JobID = iteration.ID
	want.Link = lore.LinkToThread("<v2>")
	require.Equal(t, want, c.syncAIPatch(extID))

	// The bug is held for the whole patch, so any version can be used to release it.
	c.holdAIPatch("<v2>", "<unhold>", false)
	want.Held = false
	require.Equal(t, want, c.syncAIPatch(extID))

	c.rejectAIPatch("<v2>")
	want.State = AIPatchDecided
	require.Equal(t, want, c.syncAIPatch(extID))

	// A new patching job starts a new patch.
	c.advanceTime(time.Hour)
	c.pollAIWorkflow(t, ai.WorkflowPatching)
	jobID = c.createAIJob(extID, string(ai.WorkflowPatching), "")
	require.Equal(t, BugAIPatch{JobID: jobID, State: AIPatchPending}, c.syncAIPatch(extID))
}

func TestAIPatchSyncPrivateStage(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	report := c.setupPrivateAIPatch(t)
	_, extID, err := email.RemoveAddrContext(report.Sender)
	require.NoError(t, err)

	// The patch is under review, but there is no link that could be shown to everybody.
	c.pollAndConfirmReport(t, "lore", "<moderation>")
	patch := c.syncAIPatch(extID)
	require.Equal(t, AIPatchCandidate, patch.State)
	require.NotZero(t, patch.Posted)
	require.Empty(t, patch.Link)

	// So bug reports don't mention the patch.
	c.incomingEmail(report.Sender, "#syz upstream\n", EmailOptCC(report.To))
	require.NotContains(t, c.pollEmailBug().Body, "AI patch candidate")
}

func TestAIPatchSyncFailedJob(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig("ains", &AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
		},
	})

	extID, jobID := c.setupAIPatchJob(t)
	// The patch of a failed job does not count.
	require.NoError(t, c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      jobID,
		Error:   "failed",
		Results: map[string]any{"PatchDiff": "diff"},
	}))
	require.Equal(t, BugAIPatch{JobID: jobID, State: AIPatchFailed}, c.syncAIPatch(extID))
}

func TestAIPatchSyncUnauthorizedHold(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig("ains", &AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
		},
		AllowedCommandAuthors: []string{"reviewer@test.com"},
	})

	extID, jobID := c.setupAIPatchJob(t)
	c.finishAIPatchJob(t, jobID, nil)
	c.pollAndConfirmReport(t, "lore", "<patch>")

	resp, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<patch>",
		MessageExtID: "<hold>",
		Author:       "someone@test.com",
		DKIM:         true,
		Hold:         &dashapi.HoldCommand{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Error)
	require.False(t, c.syncAIPatch(extID).Held)
}

func TestAIPatchMention(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig("ains", &AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
		},
	})
	const mention = `
AI patch candidate, your feedback is welcome:
Test Subject
https://lore.kernel.org/all/patch/T/

`

	build := testBuild(1)
	require.NoError(t, c.aiClient.UploadBuild(build))
	crash := testCrash(build, 1)
	_, err := c.aiClient.ReportCrash(crash)
	require.NoError(t, err)
	extID := c.aiClient.pollEmailExtID()

	c.pollAIWorkflow(t, ai.WorkflowPatching)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")
	c.finishAIPatchJob(t, jobID, nil)
	c.pollAndConfirmReport(t, "lore", "<patch>")
	c.syncAIPatch(extID)

	// The patch is mentioned while it's waiting for a review.
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("syz repro")
	_, err = c.aiClient.ReportCrash(crash)
	require.NoError(t, err)
	require.Contains(t, c.pollEmailBug().Body, mention)

	// A rejected patch is not mentioned, even if the rejection is not synced yet.
	c.rejectAIPatch("<patch>")
	crash.ReproC = []byte("c repro")
	_, err = c.aiClient.ReportCrash(crash)
	require.NoError(t, err)
	require.NotContains(t, c.pollEmailBug().Body, "AI patch candidate")
}
