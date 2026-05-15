// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"google.golang.org/appengine/v2"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/require"
)

func TestAIExternalReporting(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	// Report a crash to create a bug.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Register workflow and create a job.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	// Mark job as done with results.
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

	// Poll for pending reports and confirm published.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	require.True(t, pollResp.Result.CanUpstream)
	require.Equal(t, "123456789012", pollResp.Result.Patch.Fixes.Hash)
	require.Equal(t, "original bug", pollResp.Result.Patch.Fixes.Title)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "moderation-msg-id",
	})
	require.NoError(t, err)

	// Upstream the result.
	resp, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "moderation-msg-id",
		Upstream:  &dashapi.UpstreamCommand{},
		Author:    "test-user",
		Source:    "lore",
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
	uiHistory, err := LoadUIJobReviewHistory(c.ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, []*uiJobReviewHistory{
		{
			Date:    c.mockedTime,
			User:    "test-user",
			Correct: aiCorrectnessCorrect,
			Source:  "lore",
			Stage:   "public",
		},
	}, uiHistory)

	// Verify Job.Correct = true.
	job, err := aidb.LoadJob(c.ctx, jobID)
	require.NoError(t, err)
	require.True(t, job.Correct.Valid)
	require.True(t, job.Correct.Bool)

	t0 := c.mockedTime
	c.advanceTime(time.Second)

	// "Report" to the public lists.
	pollResp, err = c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	require.False(t, pollResp.Result.CanUpstream)
	require.Equal(t, &dashapi.NewReportResult{
		Subject:    "Test Subject",
		Body:       "Test Body",
		Version:    1,
		GitDiff:    "diff",
		BaseCommit: "commit",
		BaseTree:   "repo",
		Authors:    []string{"test-user"},
		Links: []string{
			appURL(c.ctx) + "/bug?extid=" + extID,
			appURL(c.ctx) + "/ai_job?id=" + jobID,
		},
		Fixes: ai.FixesTag{
			Hash:  "123456789012",
			Title: "original bug",
		},
		ReportedBy: []string{"syzbot+" + extID + "@" + appengine.AppID(c.ctx) + ".appspotmail.com"},
	}, pollResp.Result.Patch)
	require.Equal(t, []string{"public@test.com"}, pollResp.Result.To)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-123",
	})
	require.NoError(t, err)

	// Verify no more pending.
	pollResp, err = c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.Nil(t, pollResp.Result)

	// Reject the patch.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "moderation-msg-id",
		Reject:    &dashapi.RejectCommand{Reason: "Bad patch"},
		Author:    "test-user",
		Source:    "lore",
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
	uiHistory, err = LoadUIJobReviewHistory(c.ctx, jobID)
	require.NoError(t, err)
	require.Equal(t, []*uiJobReviewHistory{
		{
			Date:    c.mockedTime,
			User:    "test-user",
			Correct: aiCorrectnessIncorrect,
			Source:  "lore",
			Stage:   "", // Rejections are not per-stage.
		},
		{
			Date:    t0,
			User:    "test-user",
			Correct: aiCorrectnessCorrect,
			Source:  "lore",
			Stage:   "public",
		},
	}, uiHistory)

	// Verify Job.Correct = false.
	job, err = aidb.LoadJob(c.ctx, jobID)
	require.NoError(t, err)
	require.True(t, job.Correct.Valid)
	require.False(t, job.Correct.Bool)
}

func TestAIReportNotFound(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	req := &dashapi.SendExternalCommandReq{
		RootExtID: "non-existent-id",
		Upstream:  &dashapi.UpstreamCommand{},
	}
	_, err := c.globalClient.AIReportCommand(req)
	require.Error(t, err)
	require.True(t, errors.Is(err, dashapi.ErrReportNotFound), "expected ErrReportNotFound, got %+v", err)
}

func TestAINoFailedJobReported(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	// Report a crash to create a bug.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Register workflow.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	// Mark job as failed.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:    jobID,
		Error: "Something went wrong",
	})
	require.NoError(t, err)

	// Nothing is reported.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.Nil(t, pollResp.Result)
}

func TestAINoParallelReports(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	aiCfg := &AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "review", ServingIntegration: "lore", MailingList: "review@test.com", NoParallelReports: false},
			{
				Name:               "lkml",
				ServingIntegration: "lore",
				MailingList:        "lkml@test.com",
				NoParallelReports:  true,
				MergePatchCc:       true,
			},
		},
	}
	c.SetAIConfig(aiCfg)

	// Report a crash to create a bug.
	build := testBuild(1)
	build.Manager = "ains"
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Register workflow.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	// Create two jobs for the same bug.
	jobID1 := c.createAIJob(extID, string(ai.WorkflowPatching), "")
	jobID2 := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID1,
		Results: map[string]any{
			"PatchDescription": "Job 1 Subject\n\nJob 1 Body",
			"PatchDiff":        "diff1",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit1",
		},
	})
	require.NoError(t, err)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID2,
		Results: map[string]any{
			"PatchDescription": "Job 2 Subject\n\nJob 2 Body",
			"PatchDiff":        "diff2",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit2",
		},
	})
	require.NoError(t, err)

	// Poll for pending reports.
	// Stage 0 ("review") allows parallel reports.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	id1 := pollResp.Result.ID

	// Confirm first report.
	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       id1,
		PublishedExtID: "msg-id-1",
	})
	require.NoError(t, err)

	// Poll again. Should return the second report.
	pollResp, err = c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	id2 := pollResp.Result.ID
	require.NotEqual(t, id1, id2)

	// Confirm second report.
	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       id2,
		PublishedExtID: "msg-id-2",
	})
	require.NoError(t, err)

	// Upstream job 1's result.
	resp, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-1",
		Upstream:  &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)

	// Second upstream should fail because that stage is exclusive.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-2",
		Upstream:  &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Error)
	require.Contains(t, resp.Error, "another report for this bug has already been sent")

	// Invalidate the first job using reject command.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-1",
		Reject:    &dashapi.RejectCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)

	// Now we can push the second job to the second stage.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-2",
		Upstream:  &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
}

func TestAIUpstreamTwice(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	// Report a crash to create a bug.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Register workflow and create a job.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	// Mark job as done.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
		},
	})
	require.NoError(t, err)

	// Poll and confirm report for "moderation" stage.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	require.Equal(t, "moderation@test.com", pollResp.Result.To[0])

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-moderation",
	})
	require.NoError(t, err)

	// Upstream the result (moves to "public").
	resp, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-moderation",
		Upstream:  &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)

	// Poll and confirm report for "public" stage.
	pollResp, err = c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	require.Equal(t, "public@test.com", pollResp.Result.To[0])

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-public",
	})
	require.NoError(t, err)

	// Try to upstream again. Should fail at determineNextStage level.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-moderation",
		Upstream:  &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Error)
	require.Contains(t, resp.Error, "a later stage public was already reported")
}

func TestAIUpstreamIdempotency(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com", MergePatchCc: true},
		},
	})

	// Report a crash to create a bug.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Register workflow and create a job.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	// Mark job as done.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
		},
	})
	require.NoError(t, err)

	// Poll and confirm report for "moderation" stage.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-moderation",
	})
	require.NoError(t, err)

	// Upstream the result.
	resp, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID:    "msg-id-moderation",
		MessageExtID: "command-msg-id",
		Source:       "lore",
		Upstream:     &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)

	// Upstream the result again with the same MessageExtID. Should be an idempotent success.
	resp, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID:    "msg-id-moderation",
		MessageExtID: "command-msg-id",
		Source:       "lore",
		Upstream:     &dashapi.UpstreamCommand{},
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
}

func TestAINoStages(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{})

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: "patching", Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, "patching", "")

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

	job, err := aidb.LoadJob(c.ctx, jobID)
	require.NoError(t, err)
	require.False(t, job.Correct.Valid)

	values := url.Values{}
	values.Set("correct", aiCorrectnessCorrect)
	_, err = c.POSTForm(fmt.Sprintf("/ai_job?id=%v", jobID), values)
	require.NoError(t, err)

	job, err = aidb.LoadJob(c.ctx, jobID)
	require.NoError(t, err)
	require.True(t, job.Correct.Valid)
	require.True(t, job.Correct.Bool)

	journal, err := aidb.LoadJobJournal(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, journal, 1)
	require.Equal(t, aidb.ActionApprove, journal[0].Action)

	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.Nil(t, pollResp.Result)
}

func TestAIUpstreamConcurrent(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com"},
		},
	})

	// 1. Setup bug and job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)
	jobID1 := c.createAIJob(extID, string(ai.WorkflowPatching), "")

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID1,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
		},
	})
	require.NoError(t, err)

	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-moderation",
	})
	require.NoError(t, err)

	// 2. Simulate comment arrival.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "msg-id-moderation",
		MessageExtID: "<comment-1>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Body: "This is a comment"},
	})
	require.NoError(t, err)

	c.advanceTime(31 * time.Minute)

	// 3. Poll for iteration job.
	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID) // This is job2 (iteration job)

	// 4. While job2 is "running", someone upstreams the report!
	respCmd, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-moderation",
		Upstream:  &dashapi.UpstreamCommand{},
		Source:    "lore",
	})
	require.NoError(t, err)
	require.Empty(t, respCmd.Error)

	// 5. Iteration job finishes.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"PatchDescription": "New Subject\n\nNew Body",
			"PatchDiff":        "new diff",
		},
	})
	require.NoError(t, err)

	// 6. Verify results are not reported for the old thread!
	// The active reporting has advanced to "public" stage due to upstream command.
	// The iteration job result (for "moderation" stage) should be aborted.

	// Poll for reports. It should return the report for "public" stage (triggered by upstream)!
	// NOT the iteration result!
	pollResp2, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	require.NoError(t, err)
	require.NotNil(t, pollResp2.Result)
	require.Equal(t, "public@test.com", pollResp2.Result.To[0])

	// Confirm and verify no more pending.
	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp2.Result.ID,
		PublishedExtID: "msg-id-public",
	})
	require.NoError(t, err)

	pollResp3, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	require.NoError(t, err)
	require.Nil(t, pollResp3.Result) // Should be nil!
}

func TestAIPatchIterationSuccess(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com"},
		},
	})

	// 1. Setup bug and job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark the job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "exact-repo",
			"KernelBranch":     "exact-branch",
			"KernelCommit":     "exact-commit",
		},
	})
	require.NoError(t, err)

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)
	reporting := reportings[0]

	// Set version to 1 for parent reporting.
	err = aidb.RunInTransaction(c.ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		mut := spanner.Update("JobReporting", []string{"ID", "Version"},
			[]any{reporting.ID, spanner.NullInt64{Int64: 1, Valid: true}})
		return tx.BufferWrite([]*spanner.Mutation{mut})
	})
	require.NoError(t, err)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting.ID,
		PublishedExtID: "<message-id-1>",
	})
	require.NoError(t, err)

	// 2. Simulate comment arrival.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<message-id-1>",
		MessageExtID: "<comment-id-1>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Body: "This is a comment"},
	})
	require.NoError(t, err)

	// 3. Poll before debounce should return nothing.
	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, "", resp.ID)

	// 4. Advance time to pass debounce (30 mins).
	c.advanceTime(31 * time.Minute)

	// 5. Poll again should return the job.
	resp, err = c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)
	require.Equal(t, "patch-iteration", resp.Workflow)
	require.Equal(t, "exact-commit", resp.Args["BaseCommit"])
	require.Equal(t, "exact-branch", resp.Args["BaseBranch"])
	require.Equal(t, "exact-repo", resp.Args["BaseRepository"])

	// Verify Args contains PatchHistory!
	var gotPatchHistory []ai.PatchHistoryEntry
	data, err := json.Marshal(resp.Args["PatchHistory"])
	require.NoError(t, err)
	err = json.Unmarshal(data, &gotPatchHistory)
	require.NoError(t, err)

	require.Len(t, gotPatchHistory, 1)
	// Zero out timestamps for comparison.
	for i := range gotPatchHistory {
		for j := range gotPatchHistory[i].Comments {
			gotPatchHistory[i].Comments[j].Timestamp = time.Time{}
		}
	}

	wantPatchHistory := []ai.PatchHistoryEntry{
		{
			Version:     1,
			Diff:        "diff",
			Description: "Test Subject\n\nTest Body",
			Comments: []ai.ExternalComment{
				{
					ExtID:  "<comment-id-1>",
					Author: "reviewer@email.com",
					Body:   "This is a comment",
					New:    true,
				},
			},
		},
	}
	require.Equal(t, wantPatchHistory, gotPatchHistory)

	// 6. Complete the job with a changelog!
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"PatchDescription": "New Subject\n\nNew Body",
			"PatchDiff":        "new diff",
			"NewChangeLog":     "- Fixed ABCD.",
			"KernelRepo":       "repo_url",
			"KernelCommit":     "repo_commit",
		},
	})
	require.NoError(t, err)

	// 6.5 Verify AIPollReport returns the new patch including the changelog.
	pollRepResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: dashapi.AIJobSourceLore})
	require.NoError(t, err)
	require.NotNil(t, pollRepResp.Result)

	gotResult := pollRepResp.Result
	wantResult := &dashapi.ReportPollResult{
		ID:          gotResult.ID,
		CanUpstream: true,
		To:          []string{"moderation@test.com"},
		Patch: &dashapi.NewReportResult{
			Subject:    "New Subject",
			Body:       "New Body",
			Version:    2,
			GitDiff:    "new diff",
			ReportedBy: []string{"syzbot+" + extID + "@" + appengine.AppID(c.ctx) + ".appspotmail.com"},
			Changelog: []dashapi.ChangelogEntry{
				{
					Version: 2,
					Text:    "- Fixed ABCD.",
				},
				{
					Version: 1,
					Link:    "https://lore.kernel.org/all/message-id-1/T/",
				},
			},
			BaseCommit: "repo_commit",
			BaseTree:   "repo_url",
			Links: []string{
				appURL(c.ctx) + "/bug?extid=" + extID,
				appURL(c.ctx) + "/ai_job?id=" + resp.ID,
			},
		},
	}
	require.Equal(t, wantResult, gotResult)

	// 7. Verify comments marked processed.
	loadedComments, err := aidb.LoadJobComments(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, loadedComments, 1)
	require.True(t, loadedComments[0].Processed)

	testExtendedPatchIteration(t, c, resp, gotResult, pollReq)
}

func testExtendedPatchIteration(t *testing.T, c *Ctx, resp *dashapi.AIJobPollResp,
	gotResult *dashapi.ReportPollResult, pollReq *dashapi.AIJobPollReq) {
	// 8. Confirm the V2 patch report.
	err := c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       gotResult.ID,
		PublishedExtID: "<message-id-2>",
	})
	require.NoError(t, err)

	// Verify R2 marked reported.
	reportings2, err := aidb.LoadJobReportings(c.ctx, resp.ID)
	require.NoError(t, err)
	require.Len(t, reportings2, 1)
	require.True(t, reportings2[0].ReportedAt.Valid)

	// 9. Simulate another comment arriving on the V2 thread.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<message-id-2>",
		MessageExtID: "<comment-id-2>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Body: "This is another comment"},
	})
	require.NoError(t, err)

	// 10. Advance time to pass debounce again.
	c.advanceTime(31 * time.Minute)

	// 11. Poll again should return the job with VERSION 3!
	resp, err = c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)
	require.Equal(t, "patch-iteration", resp.Workflow)

	// Verify Args contains PatchHistory for V2!
	var gotPatchHistory2 []ai.PatchHistoryEntry
	data, err := json.Marshal(resp.Args["PatchHistory"])
	require.NoError(t, err)
	err = json.Unmarshal(data, &gotPatchHistory2)
	require.NoError(t, err)

	require.Len(t, gotPatchHistory2, 1)
	// Zero out timestamps for comparison.
	for i := range gotPatchHistory2 {
		for j := range gotPatchHistory2[i].Comments {
			gotPatchHistory2[i].Comments[j].Timestamp = time.Time{}
		}
	}

	wantPatchHistory := []ai.PatchHistoryEntry{
		{
			Version:     2,
			Diff:        "new diff",
			Description: "New Subject\n\nNew Body",
			Comments: []ai.ExternalComment{
				{
					ExtID:  "<comment-id-2>",
					Author: "reviewer@email.com",
					Body:   "This is another comment",
					New:    true,
				},
			},
		},
	}
	require.Equal(t, wantPatchHistory, gotPatchHistory2)

	// 12. Complete the job and verify version in report.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"PatchDescription": "Subject V3\n\nBody V3",
			"PatchDiff":        "diff V3",
			"NewChangeLog":     "- Reverted to standard formatting.",
		},
	})
	require.NoError(t, err)

	pollRepResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: dashapi.AIJobSourceLore})
	require.NoError(t, err)
	require.NotNil(t, pollRepResp.Result)

	gotResult = pollRepResp.Result

	reportings, err := aidb.LoadJobReportings(c.ctx, resp.ID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)

	require.Equal(t, 3, gotResult.Patch.Version)
	require.Equal(t, []dashapi.ChangelogEntry{
		{
			Version: 3,
			Text:    "- Reverted to standard formatting.",
		},
		{
			Version: 2,
			Link:    "https://lore.kernel.org/all/message-id-2/T/",
			Text:    "- Fixed ABCD.",
		},
		{
			Version: 1,
			Link:    "https://lore.kernel.org/all/message-id-1/T/",
		},
	}, gotResult.Patch.Changelog)

	// 13. Confirm the V3 patch report.
	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       gotResult.ID,
		PublishedExtID: "<message-id-3>",
	})
	require.NoError(t, err)

	// 14. Upstream the V3 result to public stage.
	respCmd, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "<message-id-3>",
		Upstream:  &dashapi.UpstreamCommand{},
		Source:    "lore",
	})
	require.NoError(t, err)
	require.Empty(t, respCmd.Error)

	// 15. Poll for reports. It should return the report for "public" stage!
	// And it should have VERSION 1!
	pollResp4, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	require.NoError(t, err)
	require.NotNil(t, pollResp4.Result)
	require.Equal(t, "public@test.com", pollResp4.Result.To[0])
	require.Equal(t, 1, pollResp4.Result.Patch.Version)
	require.Empty(t, pollResp4.Result.Patch.Changelog)
}

// TestAIPatchIterationBackoff verifies that the system respects the backoff period
// after a failed iteration job. It ensures that new jobs are not created too quickly
// even if new comments arrive, to prevent spamming the LLM or agent on persistent failures.
func TestAIPatchIterationBackoff(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	// 1. Setup bug and initial patching job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark the job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	// Complete the initial patching job successfully.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Desc Subject\n\nDesc Body",
			"PatchDiff":        "diff",
			"KernelCommit":     "exact-commit-hash",
			"KernelRepo":       "exact-repo",
			"KernelBranch":     "exact-branch",
		},
	})
	require.NoError(t, err)

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	reporting := reportings[0]

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting.ID,
		PublishedExtID: "<msg-1>",
	})
	require.NoError(t, err)

	// 2. Simulate a comment arriving on the thread.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<msg-1>",
		MessageExtID: "<comment-1>",
		Author:       "rev@email.com",
		Comment:      &dashapi.CommentCommand{Body: "Comment"},
	})
	require.NoError(t, err)

	// Advance time to pass the debounce period (30 mins).
	c.advanceTime(31 * time.Minute)

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}

	// 3. Poll for jobs. A new iteration job should be created.
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ID)

	// Verify that the iteration job accurately copied the BaseCommit overrides from the parent!
	require.Equal(t, "exact-commit-hash", resp.Args["BaseCommit"])
	require.Equal(t, "exact-repo", resp.Args["BaseRepository"])
	require.Equal(t, "exact-branch", resp.Args["BaseBranch"])

	// 4. Simulate the iteration job failing (e.g., LLM error).
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:    resp.ID,
		Error: "LLM failed",
	})
	require.NoError(t, err)

	// 5. Simulate another comment arriving after the failure.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<msg-1>",
		MessageExtID: "<comment-2>",
		Author:       "rev@email.com",
		Comment:      &dashapi.CommentCommand{Body: "Comment 2"},
	})
	require.NoError(t, err)

	// Advance time by some amount less than the backoff period (1 hour).
	c.advanceTime(6 * time.Minute)

	// 6. Poll again. Should NOT get a new job because we are in backoff.
	resp2, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, "", resp2.ID)

	// 7. Advance time past the backoff period.
	c.advanceTime(1 * time.Hour)

	// 8. Poll again. Now we should get a new job.
	resp3, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp3.ID)
}

// TestAIPatchIterationAutoTriggerDisabled verifies that the system does not
// autonomously iterate on comments if the stage configuration has AddressComments
// set to false.
func TestAIPatchIterationAutoTriggerDisabled(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			// Explicitly disable auto-triggering.
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: false},
		},
	})

	// 1. Setup bug and patching job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      jobID,
		Results: map[string]any{"PatchDescription": "Desc1 Subject\n\nDesc1 Body", "PatchDiff": "diff1"},
	})
	require.NoError(t, err)

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	reporting := reportings[0]

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting.ID,
		PublishedExtID: "<msg-1>",
	})
	require.NoError(t, err)

	// 2. Simulate comment arrival.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<msg-1>",
		MessageExtID: "<comment-1>",
		Author:       "rev@email.com",
		Comment:      &dashapi.CommentCommand{Body: "This is a comment"},
	})
	require.NoError(t, err)

	// 3. Advance time to pass the debounce period (30 mins).
	c.advanceTime(31 * time.Minute)

	// 4. Poll for iteration jobs. It should NOT return a job because AddressComments is false.
	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, "", resp.ID)
}

// TestAIPatchIterationStaleThread verifies that the system stops iterating on
// threads for obsolete patch versions when a newer patch version has been created.
// It ensures that comments on old threads are marked as processed to avoid continuous polling.
func TestAIPatchIterationStaleThread(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	// 1. Setup bug and V1 patching job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID1 := c.createAIJob(extID, "patching", "")

	// Poll to mark job1 as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	// Complete V1 job.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      jobID1,
		Results: map[string]any{"PatchDescription": "Desc1 Subject\n\nDesc1 Body", "PatchDiff": "diff1"},
	})
	require.NoError(t, err)

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID1)
	require.NoError(t, err)
	reporting1 := reportings[0]

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting1.ID,
		PublishedExtID: "<msg-1>",
	})
	require.NoError(t, err)

	// 2. Simulate a comment arriving on the V1 thread.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<msg-1>",
		MessageExtID: "<comment-1>",
		Author:       "rev@email.com",
		Comment:      &dashapi.CommentCommand{Body: "Comment on V1"},
	})
	require.NoError(t, err)

	// 3. Now create a V2 patching job using helper.
	jobID2 := c.createAIJob(extID, "patching", "")

	// Poll to mark job2 as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	c.advanceTime(1 * time.Second) // Ensure later CreatedAt.

	// Complete V2 job.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      jobID2,
		Results: map[string]any{"PatchDescription": "Desc2 Subject\n\nDesc2 Body", "PatchDiff": "diff2"},
	})
	require.NoError(t, err)

	// Advance time past debounce.
	c.advanceTime(31 * time.Minute)

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatchIteration, Name: "patch-iteration"},
		},
	}

	// 4. Poll for iteration jobs.
	// Should NOT get a job for V1 comments because a newer reporting (V2) exists.
	resp, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, "", resp.ID)
}

func TestAIPatchIterationReplySuccess(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com"},
		},
	})

	// 1. Setup bug and job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark the job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

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

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)
	reporting := reportings[0]

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting.ID,
		PublishedExtID: "<message-id-1>",
	})
	require.NoError(t, err)

	// 2. Simulate comment arrival.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<message-id-1>",
		MessageExtID: "<comment-id-1>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Subject: "Re: [PATCH RFC] Test Subject", Body: "This is a comment"},
	})
	require.NoError(t, err)

	// 3. Advance time to pass debounce (30 mins).
	c.advanceTime(31 * time.Minute)

	// 4. Poll should return the job.
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

	// Simulate a second comment arriving WHILE the job is running (or polled).
	// This represents the race condition.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<message-id-1>",
		MessageExtID: "<comment-id-2>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Subject: "Re: [PATCH RFC] Test Subject", Body: "This is a concurrent comment"},
	})
	require.NoError(t, err)

	// 5. Complete the job with REPLIES only.
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Replies": []map[string]any{
				{"ReplyTo": "<comment-id-1>", "Text": "I will fix it."},
			},
		},
	})
	require.NoError(t, err)

	// 6. Verify AIPollReport returns the reply.
	pollRepResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: dashapi.AIJobSourceLore})
	require.NoError(t, err)
	require.NotNil(t, pollRepResp.Result)

	gotResult := pollRepResp.Result
	wantResult := &dashapi.ReportPollResult{
		ID:          gotResult.ID,
		CanUpstream: false,
		To:          []string{"moderation@test.com"},
		Replies: []*dashapi.ReplyResult{
			{Body: "I will fix it.", ReplyExtID: "<comment-id-1>", ReplyAuthor: "reviewer@email.com"},
		},
		ThreadSubject: "Re: [PATCH RFC] Test Subject",
	}
	require.Equal(t, wantResult, gotResult)

	// Confirm the reply-only report so it has a PublishedExtID in the database.
	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       gotResult.ID,
		PublishedExtID: "<reply-message-id-1>",
	})
	require.NoError(t, err)

	// Verify that upstreaming this reply-only job is rejected.
	// By using its specific PublishedExtID as the RootExtID, we force
	// lookupJobByExtReq to load the reply-only job directly.
	upstreamReq := &dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<reply-message-id-1>",
		MessageExtID: "<reply-message-id-1>",
		Author:       "approver@email.com",
		Upstream:     &dashapi.UpstreamCommand{},
	}
	upstreamResp, err := c.globalClient.AIReportCommand(upstreamReq)
	require.NoError(t, err)
	require.Contains(t, upstreamResp.Error, "Cannot upstream a job that did not produce a patch")

	// 7. Advance time again to pass debounce for the second comment.
	c.advanceTime(31 * time.Minute)

	// 8. Poll should return a NEW job for the second comment.
	resp2, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp2.ID)
	require.NotEqual(t, resp.ID, resp2.ID) // Must be a new job.
}

func TestAIManualPushToReporting(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// 1. Finish a job with no AI stages configured (no reporting generated).
	c.SetAIConfig(&AIConfig{})

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName: "test", CodeRevision: "test-rev", Workflows: []dashapi.AIWorkflow{{Type: "patching", Name: "patching"}},
	})
	require.NoError(t, err)
	jobID := c.createAIJob(extID, "patching", "")
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID, Results: map[string]any{
			"PatchDiff":        "diff",
			"PatchDescription": "Subject\n\nBody",
			"KernelCommit":     "abcd",
			"KernelRepo":       "git://repo",
		},
	})
	require.NoError(t, err)

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	require.Empty(t, reportings)

	// 2. Add an AI stage to the config and push the job.
	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{{Name: "public", ServingIntegration: "lore"}},
	})

	values := url.Values{}
	values.Set("push_to_reporting", "1")
	_, err = c.POSTForm(fmt.Sprintf("/ai_job?id=%v", jobID), values)
	require.NoError(t, err)

	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)
	// Make sure the poll returns our manually pushed job.
	require.Equal(t, "Subject", pollResp.Result.Patch.Subject)
}

func TestAIAssessmentNoReport(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com"},
		},
		SecurityPrio: func(*Bug, ai.AssessmentSecurityOutputs) BugPrio { return "" },
	})

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	crash.Title = "WARNING: any type of bug"
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	// Register the workflow first.
	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentSecurity, Name: string(ai.WorkflowAssessmentSecurity)},
		},
	})
	require.NoError(t, err)

	// Manually create the job since it's not automatically created for generic bugs.
	jobID := c.createAIJob(extID, string(ai.WorkflowAssessmentSecurity), "")

	// Poll again to pick up the job and assign it to the agent.
	pollResp2, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentSecurity, Name: string(ai.WorkflowAssessmentSecurity)},
		},
	})
	require.NoError(t, err)
	require.Equal(t, jobID, pollResp2.ID)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"Explanation": "Test",
			"Exploitable": false,
		},
	})
	require.NoError(t, err)

	values := url.Values{}
	values.Set("correct", aiCorrectnessCorrect)
	_, err = c.POSTForm(fmt.Sprintf("/ai_job?id=%v", jobID), values)
	require.NoError(t, err)

	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.Nil(t, pollResp.Result)
}

func TestAIPatchIterationEmptyResult(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
		},
	})

	// 1. Setup bug and job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark the job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

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

	reportings, err := aidb.LoadJobReportings(c.ctx, jobID)
	require.NoError(t, err)
	require.Len(t, reportings, 1)
	reporting := reportings[0]

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       reporting.ID,
		PublishedExtID: "<message-id-1>",
	})
	require.NoError(t, err)

	// 2. Simulate comment arrival.
	_, err = c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		Source:       dashapi.AIJobSourceLore,
		RootExtID:    "<message-id-1>",
		MessageExtID: "<comment-id-1>",
		Author:       "reviewer@email.com",
		Comment:      &dashapi.CommentCommand{Body: "This is a comment"},
	})
	require.NoError(t, err)

	// 3. Advance time to pass debounce (30 mins).
	c.advanceTime(31 * time.Minute)

	// 4. Poll should return the job.
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

	// 5. Complete the job with no output (empty diff, no replies).
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"PatchDiff": "",
			"Replies":   []any{},
		},
	})
	require.NoError(t, err)

	// 6. Verify AIPollReport returns nothing because the job had no output.
	pollRepResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{Source: dashapi.AIJobSourceLore})
	require.NoError(t, err)
	require.Nil(t, pollRepResp.Result)

	// 7. Advance time again to ensure the comment doesn't re-trigger a job (it should be marked as processed).
	c.advanceTime(31 * time.Minute)
	resp2, err := c.agentClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Empty(t, resp2.ID)
}

func TestAIPatchFilter(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{
		Stages: []AIPatchStageConfig{
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com", AddressComments: true},
			{Name: "public", ServingIntegration: "lore", MailingList: "public@test.com"},
		},
	})

	// 1. Setup bug and job.
	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	crash.Title = "test crash title"
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	reply, err := c.AuthGET(AccessAdmin, "/ains")
	c.expectOK(err)
	require.Contains(t, string(reply), crash.Title)

	// Initially, the bug shouldn't be visible in the with_ai_patch filter.
	reply, err = c.AuthGET(AccessAdmin, "/ains?with_ai_patch=true")
	c.expectOK(err)
	require.NotContains(t, string(reply), crash.Title)

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	jobID := c.createAIJob(extID, "patching", "")

	// Poll to mark the job as started.
	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "test-agent",
		CodeRevision: "test-rev",
		Workflows:    []dashapi.AIWorkflow{{Type: ai.WorkflowPatching, Name: "patching"}},
	})
	require.NoError(t, err)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID,
		Results: map[string]any{
			"PatchDescription": "Test Subject\n\nTest Body",
			"PatchDiff":        "diff",
			"KernelRepo":       "exact-repo",
			"KernelBranch":     "exact-branch",
			"KernelCommit":     "exact-commit",
		},
	})
	require.NoError(t, err)

	job, err := aidb.LoadJob(c.ctx, jobID)
	require.NoError(t, err)
	bugIDs, err := aidb.LoadBugIDsWithPendingPatch(c.ctx, job.Namespace, []ai.WorkflowType{ai.WorkflowPatching})
	require.NoError(t, err)
	require.Len(t, bugIDs, 1)

	// Now it should be visible!
	reply, err = c.AuthGET(AccessAdmin, "/ains?with_ai_patch=true")
	c.expectOK(err)
	require.Contains(t, string(reply), crash.Title)

	// Poll and confirm report for "moderation" stage.
	pollResp, err := c.globalClient.AIPollReport(&dashapi.PollExternalReportReq{
		Source: "lore",
	})
	require.NoError(t, err)
	require.NotNil(t, pollResp.Result)

	err = c.globalClient.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       pollResp.Result.ID,
		PublishedExtID: "msg-id-moderation",
	})
	require.NoError(t, err)

	// Issue an upstream command.
	respCmd, err := c.globalClient.AIReportCommand(&dashapi.SendExternalCommandReq{
		RootExtID: "msg-id-moderation",
		Upstream:  &dashapi.UpstreamCommand{},
		Source:    "lore",
	})
	require.NoError(t, err)
	require.Empty(t, respCmd.Error)

	// Now it should no longer be visible!
	reply, err = c.AuthGET(AccessAdmin, "/ains?with_ai_patch=true")
	c.expectOK(err)
	require.NotContains(t, string(reply), crash.Title)
}
