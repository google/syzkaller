// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func TestAIMigrations(t *testing.T) {
	// Ensure spanner DDL files are syntax-correct and idempotent.
	// NewSpannerCtx already run the "up" statements, so we start with "down".
	c := NewSpannerCtx(t)
	defer c.Close()

	up, err := loadUpDDLStatements()
	require.NoError(t, err)
	down, err := loadDownDDLStatements()
	require.NoError(t, err)

	require.NoError(t, executeSpannerDDL(c.ctx, down))
	require.NoError(t, executeSpannerDDL(c.ctx, up))
	require.NoError(t, executeSpannerDDL(c.ctx, down))
	require.NoError(t, executeSpannerDDL(c.ctx, up))
}

func TestAIBugWorkflows(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)

	// KCSAN bug w/o repro.
	crash1 := testCrash(build, 1)
	crash1.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash1)
	bugExtID1 := c.aiClient.pollEmailExtID()
	kcsanBug, _, _ := c.loadBug(bugExtID1)

	// Bug2: KASAN bug with repro.
	crash2 := testCrashWithRepro(build, 2)
	crash2.Title = "KASAN: head-use-after-free in foo"
	c.aiClient.ReportCrash(crash2)
	bugExtID2 := c.aiClient.pollEmailExtID()
	kasanBug, _, _ := c.loadBug(bugExtID2)

	requireWorkflows := func(bug *Bug, want []string) {
		got, err := aiBugWorkflows(c.ctx, bug)
		require.NoError(t, err)
		var names []string
		for _, w := range got {
			names = append(names, w.Name)
		}
		require.Equal(t, want, names)
	}
	requireWorkflows(kcsanBug, nil)
	requireWorkflows(kasanBug, nil)

	_, err := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
			{Type: "patching", Name: "patching-foo"},
			{Type: "patching", Name: "patching-bar"},
		},
	})
	require.NoError(t, err)

	// This should make patching-foo inactive.
	c.advanceTime(2 * 24 * time.Hour)

	_, err = c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
			{Type: "patching", Name: "patching-bar"},
			{Type: "patching", Name: "patching-baz"},
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
		},
	})
	require.NoError(t, err)

	_, err = c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
			{Type: "patching", Name: "patching-bar"},
			{Type: "patching", Name: "patching-qux"},
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
			{Type: "assessment-kcsan", Name: "assessment-kcsan-foo"},
		},
	})
	require.NoError(t, err)

	requireWorkflows(kcsanBug, []string{"assessment-kcsan", "assessment-kcsan-foo"})
	requireWorkflows(kasanBug, []string{"patching", "patching-bar", "patching-baz", "patching-qux"})
}

func TestAIJob(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	c.aiClient.pollEmailBug()

	resp, err := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, resp.ID, "")
	require.Equal(t, resp.Workflow, "assessment-kcsan")
	require.Equal(t, resp.Args, map[string]any{
		"BugTitle":        "KCSAN: data-race in foo / bar",
		"CrashReport":     "report1",
		"KernelRepo":      "repo1",
		"KernelCommit":    "1111111111111111111111111111111111111111",
		"KernelConfig":    "config1",
		"SyzkallerCommit": "syzkaller_commit1",
		"ReproOpts":       "",
	})

	resp2, err2 := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
		},
	})
	require.NoError(t, err2)
	require.Equal(t, resp2.ID, "")

	require.NoError(t, c.aiClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:     0,
			Type:    trajectory.SpanFlow,
			Name:    "assessment-kcsan",
			Started: c.mockedTime,
		},
	}))

	require.NoError(t, c.aiClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:     1,
			Type:    trajectory.SpanAgent,
			Name:    "agent",
			Prompt:  "do something",
			Started: c.mockedTime,
		},
	}))

	require.NoError(t, c.aiClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:      1,
			Type:     trajectory.SpanAgent,
			Name:     "agent",
			Prompt:   "do something",
			Started:  c.mockedTime,
			Finished: c.mockedTime.Add(time.Second),
			Reply:    "something",
		},
	}))

	require.NoError(t, c.aiClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:      0,
			Type:     trajectory.SpanFlow,
			Name:     "assessment-kcsan",
			Started:  c.mockedTime,
			Finished: c.mockedTime.Add(time.Second),
		},
	}))

	require.NoError(t, c.aiClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Patch":       "patch",
			"Explanation": "foo",
			"Number":      1,
			"Bool":        true,
		},
	}))
}

func TestAIAssessmentKCSAN(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	resp, err := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
		},
	})
	require.NoError(t, err)
	require.Equal(t, resp.Workflow, string(ai.WorkflowAssessmentKCSAN))

	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v", resp.ID))
	require.NoError(t, err)

	// Since the job is not completed, setting correctness must fail.
	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v&correct=%v", resp.ID, aiCorrectnessCorrect))
	require.Error(t, err)

	require.NoError(t, c.aiClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Confident":   true,
			"Benign":      true,
			"Explanation": "I don't care about races.",
		},
	}))

	// Now setting correctness must not fail.
	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v&correct=%v", resp.ID, aiCorrectnessCorrect))
	require.NoError(t, err)

	// Verify history via UI helper to also test parsing logic.
	history, err := aidb.LoadJobJournal(c.ctx, resp.ID, aidb.ActionJobReview)
	require.NoError(t, err)
	uiHistory := makeUIJobReviewHistory(history)
	require.Len(t, uiHistory, 1)
	require.Equal(t, uiHistory[0].Correct, aiCorrectnessCorrect)
	require.NotEmpty(t, uiHistory[0].User)

	bug, _, _ := c.loadBug(extID)
	labels := bug.LabelValues(RaceLabel)
	require.Len(t, labels, 1)
	require.Equal(t, labels[0].Value, BenignRace)

	c.advanceTime(time.Second)

	// Re-mark the result as incorrect, this should remove the label.
	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v&correct=%v", resp.ID, aiCorrectnessIncorrect))
	require.NoError(t, err)

	history, err = aidb.LoadJobJournal(c.ctx, resp.ID, aidb.ActionJobReview)
	require.NoError(t, err)
	uiHistory = makeUIJobReviewHistory(history)
	require.Len(t, uiHistory, 2)
	require.Equal(t, uiHistory[0].Correct, aiCorrectnessIncorrect)
	require.Equal(t, uiHistory[1].Correct, aiCorrectnessCorrect)

	bug, _, _ = c.loadBug(extID)
	labels = bug.LabelValues(RaceLabel)
	require.Len(t, labels, 0)
}

func TestAIJobsFiltering(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	c.aiClient.pollEmailBug()

	pollResp, err := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
			{Type: ai.WorkflowPatching, Name: "patching"},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, pollResp.ID)

	resp, err := c.GET("/ains/ai")
	require.NoError(t, err)
	require.Contains(t, string(resp), "KCSAN: data-race")

	// Filter by correct workflow.
	resp, err = c.GET("/ains/ai?workflow=" + string(ai.WorkflowAssessmentKCSAN))
	require.NoError(t, err)
	require.Contains(t, string(resp), "KCSAN: data-race")

	// Filter by usage of another workflow (should hide it).
	resp, err = c.GET("/ains/ai?workflow=patching")
	require.NoError(t, err)
	require.NotContains(t, string(resp), "KCSAN: data-race")
}

func TestAIJobCustomCommit(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)

	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	bug, _, _ := c.loadBug(extID)

	_, err := c.aiClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: "patching"},
		},
	})
	require.NoError(t, err)

	vals := url.Values{}
	vals.Add("ai-job-create", string(ai.WorkflowPatching))
	vals.Add("base_commit_type", "custom")
	vals.Add("base_commit", "custom123")

	_, err = c.POSTForm(fmt.Sprintf("/bug?id=%v", bug.keyHash(c.ctx)), vals)
	require.NoError(t, err)

	jobs, err := aidb.LoadBugJobs(c.ctx, bug.keyHash(c.ctx))
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	job := jobs[0]

	require.True(t, job.Args.Valid)
	args := job.Args.Value.(map[string]any)
	require.Equal(t, "custom123", args["FixedBaseCommit"])
}
