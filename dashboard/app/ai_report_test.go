// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

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
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
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
			"PatchDescription": "Test Description",
			"PatchDiff":        "diff",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit",
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
		Subject:    "Test Description",
		Body:       "Test Description",
		Version:    1,
		GitDiff:    "diff",
		BaseCommit: "commit",
		BaseTree:   "repo",
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
			"PatchDescription": "Job 1 Description",
			"PatchDiff":        "diff1",
			"KernelRepo":       "repo",
			"KernelCommit":     "commit1",
		},
	})
	require.NoError(t, err)

	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: jobID2,
		Results: map[string]any{
			"PatchDescription": "Job 2 Description",
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
			{Name: "moderation", ServingIntegration: "lore", MailingList: "moderation@test.com"},
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
			"PatchDescription": "Test Description",
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
			"PatchDescription": "Test Description",
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
