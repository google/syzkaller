// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
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

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-bug-workflow",
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

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-bug-workflow",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
			{Type: "patching", Name: "patching-bar"},
			{Type: "patching", Name: "patching-baz"},
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
		},
	})
	require.NoError(t, err)

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-bug-workflow-2",
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

func TestAIRestrictedClient(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	bug, _, _ := c.loadBug(extID)

	_, err := c.POSTForm(fmt.Sprintf("/bug?id=%v", bug.keyHash(c.ctx)),
		url.Values{"ai-job-create": []string{"patching"}})
	require.NoError(t, err)

	restrictedClient := c.makeClient(agentRestrictedClient, agentRestrictedKey, false)
	_, err = restrictedClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(),
		`the client is not allowed to execute AI jobs without "-foobar" suffix`))

	job, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})
	require.NoError(t, err)
	require.True(t, job.ID != "")

	job, err = restrictedClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client2",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching-foobar"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, job.ID, "")

	_, err = c.POSTForm(fmt.Sprintf("/bug?id=%v", bug.keyHash(c.ctx)),
		url.Values{"ai-job-create": []string{"patching-foobar"}})
	require.NoError(t, err)

	job, err = restrictedClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client3",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching-foobar"},
		},
	})
	require.NoError(t, err)
	require.True(t, job.ID != "")
	require.Equal(t, job.Workflow, "patching-foobar")

	_, err = restrictedClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "restricted-client4",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
			{Type: "patching", Name: "patching-foobar"},
		},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(),
		`the client is not allowed to execute AI jobs without "-foobar" suffix`))
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

	resp, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-job",
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
		"CrashLog":        "log1",
		"KernelRepo":      "repo1",
		"KernelCommit":    "1111111111111111111111111111111111111111",
		"KernelConfig":    "config1",
		"SyzkallerCommit": "syzkaller_commit1",
		"ReproSyz":        "",
		"ReproC":          "",
		"ReproOpts":       "",
		"BaseRepository":  "git://ai/base.git",
		"BaseBranch":      "ai-base",
		"BaseCommit":      "RC",
	})

	resp2, err2 := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-job2",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "assessment-kcsan", Name: "assessment-kcsan"},
		},
	})
	require.NoError(t, err2)
	require.Equal(t, resp2.ID, "")

	require.NoError(t, c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:     0,
			Type:    trajectory.SpanFlow,
			Name:    "assessment-kcsan",
			Started: c.mockedTime,
		},
	}))

	require.NoError(t, c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:     1,
			Type:    trajectory.SpanAgent,
			Name:    "agent",
			Prompt:  "do something",
			Started: c.mockedTime,
		},
	}))

	require.NoError(t, c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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

	require.NoError(t, c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:      0,
			Type:     trajectory.SpanFlow,
			Name:     "assessment-kcsan",
			Started:  c.mockedTime,
			Finished: c.mockedTime.Add(time.Second),
		},
	}))

	require.NoError(t, c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Explanation": "foo",
			"Number":      1,
			"Bool":        true,
		},
	}))
}

func TestAIJobNotFound(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	_, err := c.GET("/ai_job?id=non-existent-id")
	require.Error(t, err)
	expectFailureStatus(t, err, http.StatusNotFound)
}

func TestAIJobActions(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	bug, _, _ := c.loadBug(extID)

	_, err := c.globalClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-name",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})
	require.NoError(t, err)

	jobCreateURL := fmt.Sprintf("/bug?id=%v&ai-job-create=patching", bug.keyHash(c.ctx))
	_, err = c.AuthGET(AccessPublic, jobCreateURL)
	require.Error(t, err)
	// Redirect to login page.
	require.Contains(t, err.Error(), fmt.Sprint(http.StatusTemporaryRedirect))
	_, err = c.AuthGET(AccessUser, jobCreateURL)
	require.NoError(t, err)

	resp, err := c.globalClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-name",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, resp.ID, "")
	require.Equal(t, resp.Workflow, "patching")
	require.Equal(t, resp.Args, map[string]any{
		"BugTitle":        "title1",
		"CrashReport":     "report1",
		"CrashLog":        "log1",
		"KernelRepo":      "repo1",
		"KernelCommit":    "1111111111111111111111111111111111111111",
		"KernelConfig":    "config1",
		"SyzkallerCommit": "syzkaller_commit1",
		"ReproSyz":        "syncfs(1)",
		"ReproC":          "int main() { return 1; }",
		"ReproOpts":       "repro opts 1",
		"BaseRepository":  "git://ai/base.git",
		"BaseBranch":      "ai-base",
		"BaseCommit":      "RC",
	})
	require.NoError(t, c.globalClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      resp.ID,
		Results: map[string]any{"PatchDiff": "diff", "PatchDescription": "description"},
	}))

	jobAssessURL := fmt.Sprintf("/ai_job?id=%v&correct=%v", resp.ID, aiCorrectnessCorrect)
	_, err = c.AuthGET(AccessPublic, jobAssessURL)
	require.Error(t, err)
	// Redirect to login page.
	require.Contains(t, err.Error(), fmt.Sprint(http.StatusTemporaryRedirect))
	_, err = c.AuthGET(AccessUser, jobAssessURL)
	require.NoError(t, err)

	// Test crash w/o C repro.
	crash2 := testCrashWithRepro(build, 2)
	crash2.ReproC = nil
	c.aiClient.ReportCrash(crash2)
	extID2 := c.aiClient.pollEmailExtID()
	bug2, _, _ := c.loadBug(extID2)

	jobCreateURL2 := fmt.Sprintf("/bug?id=%v&ai-job-create=patching", bug2.keyHash(c.ctx))
	_, err = c.AuthGET(AccessUser, jobCreateURL2)
	require.NoError(t, err)

	resp2, err := c.globalClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-name2",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "patching", Name: "patching"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, resp2.ID, "")
	require.Equal(t, resp2.Workflow, "patching")
	require.Equal(t, resp2.Args, map[string]any{
		"BugTitle":        "title2",
		"CrashReport":     "report2",
		"CrashLog":        "log2",
		"KernelRepo":      "repo1",
		"KernelCommit":    "1111111111111111111111111111111111111111",
		"KernelConfig":    "config1",
		"SyzkallerCommit": "syzkaller_commit1",
		"ReproSyz":        "syncfs(2)",
		"ReproC":          "",
		"ReproOpts":       "repro opts 2",
		"BaseRepository":  "git://ai/base.git",
		"BaseBranch":      "ai-base",
		"BaseCommit":      "RC",
	})
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

	resp, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-test-assessment",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
		},
	})
	require.NoError(t, err)
	require.Equal(t, resp.Workflow, string(ai.WorkflowAssessmentKCSAN))

	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v", resp.ID))
	require.NoError(t, err)

	// Verify JSON output.
	respJSON, err := c.GET(fmt.Sprintf("/ai_job?id=%v&json=1", resp.ID))
	require.NoError(t, err)
	require.Contains(t, string(respJSON), `"Trajectory"`)

	// Since the job is not completed, setting correctness must fail.
	_, err = c.GET(fmt.Sprintf("/ai_job?id=%v&correct=%v", resp.ID, aiCorrectnessCorrect))
	require.Error(t, err)

	require.NoError(t, c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
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
	uiHistory, err := LoadUIJobReviewHistory(c.ctx, resp.ID)
	require.NoError(t, err)
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

	uiHistory, err = LoadUIJobReviewHistory(c.ctx, resp.ID)
	require.NoError(t, err)
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

	pollResp, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "some-agent",
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

	// Verify JSON output.
	resp, err = c.GET("/ains/ai?json=1")
	require.NoError(t, err)
	require.Contains(t, string(resp), `"Workflow": "assessment-kcsan"`)
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

	_, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "some-agent",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: "patching"},
		},
	})
	require.NoError(t, err)

	c.createAIJob(extID, string(ai.WorkflowPatching), "custom123")

	jobs, err := aidb.LoadBugJobs(c.ctx, bug.keyHash(c.ctx))
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	job := jobs[0]

	require.True(t, job.Args.Valid)
	args := job.Args.Value.(map[string]any)
	require.Equal(t, "custom123", args["BaseCommit"])
}

func TestAIJobAutoCreate(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	c.aiClient.pollEmailExtID()

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "agent-test-auto-create",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
		},
	}
	// KCSAN job should be created.
	pollResp0, _ := c.agentClient.AIJobPoll(pollReq)
	require.NotEqual(t, pollResp0.ID, "")

	// This job failed, and should be recreated after a day or so.
	c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:    pollResp0.ID,
		Error: "error",
	})
	c.advanceTime(24 * time.Hour)
	pollResp3, _ := c.agentClient.AIJobPoll(pollReq)
	require.NotEqual(t, pollResp3.ID, "")
	require.NotEqual(t, pollResp3.ID, pollResp0.ID)

	// This job failed, and should also be recreated, but now after 2 days.
	c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:    pollResp3.ID,
		Error: "error",
	})
	c.advanceTime(36 * time.Hour)
	pollResp4, _ := c.agentClient.AIJobPoll(pollReq)
	require.Equal(t, pollResp4.ID, "")

	c.advanceTime(24 * time.Hour)
	pollResp5, _ := c.agentClient.AIJobPoll(pollReq)
	require.NotEqual(t, pollResp5.ID, "")
	require.NotEqual(t, pollResp5.ID, pollResp3.ID)

	// This finishes successfully, and must never be recreated again.
	c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID: pollResp5.ID,
	})

	c.advanceTime(10 * 24 * time.Hour)
	pollResp6, _ := c.agentClient.AIJobPoll(pollReq)
	require.Equal(t, pollResp6.ID, "")
	c.advanceTime(30 * 24 * time.Hour)
	pollResp7, _ := c.agentClient.AIJobPoll(pollReq)
	require.Equal(t, pollResp7.ID, "")
}

func TestAIPendingJobs(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	// Initial poll for only "patching". Ensures "assessment-kcsan" is left in pending.
	pollResp, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "patching-agent",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: "patching-job"},
		},
	})
	require.NoError(t, err)
	require.Empty(t, pollResp.ID) // No patching jobs for KCSAN

	// No AI jobs should be created yet since the KCSAN workflow is just pending.
	bug, _, _ := c.loadBug(extID)
	jobs, err := aidb.LoadBugJobs(c.ctx, bug.keyHash(c.ctx))
	require.NoError(t, err)
	require.Empty(t, jobs)

	// Poll for "assessment-kcsan" should pick up the pending job via Phase 1 fast-path.
	pollRespKcsan, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "kcsan-agent",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowAssessmentKCSAN, Name: "kcsan-job"},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, pollRespKcsan.ID)
	require.Equal(t, "kcsan-job", pollRespKcsan.Workflow)
}

func TestAIJobParallelPoll(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Title = "KCSAN: data-race in foo / bar"
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	// Spawn multiple routines to poll for jobs concurrently.
	var eg errgroup.Group
	const numPollers = 15
	var assignedJobs int32
	for i := range numPollers {
		eg.Go(func() error {
			pollResp, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
				AgentName:    fmt.Sprintf("agent-%v", i),
				CodeRevision: prog.GitRevision,
				Workflows: []dashapi.AIWorkflow{
					{Type: ai.WorkflowAssessmentKCSAN, Name: "kcsan-job"},
				},
			})
			if err == nil && pollResp.ID != "" {
				atomic.AddInt32(&assignedJobs, 1)
			}
			return err
		})
	}
	require.NoError(t, eg.Wait())

	require.Equal(t, int32(1), assignedJobs)

	// Ensure exactly 1 Job entity actually exists in the Datastore.
	bug, _, _ := c.loadBug(extID)
	jobs, err := aidb.LoadBugJobs(c.ctx, bug.keyHash(c.ctx))
	require.NoError(t, err)
	require.Equal(t, 1, len(jobs))
}

func TestAIAgentLastActive(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	agentName := "test-agent-123"
	pollReq := &dashapi.AIJobPollReq{
		AgentName:    agentName,
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowRepro, Name: string(ai.WorkflowRepro)},
		},
	}
	c.agentClient.AIJobPoll(pollReq)
	c.createAIJob(extID, string(ai.WorkflowRepro), "")
	c.advanceTime(time.Hour)

	// Poll, get the repro job and verify the last active timestamp.
	pollResp, _ := c.agentClient.AIJobPoll(pollReq)
	require.NotEqual(t, pollResp.ID, "")

	agent, err := aidb.LoadAgent(c.ctx, agentName)
	require.NoError(t, err)
	require.WithinDuration(t, c.mockedTime, agent.LastActive, 30*time.Second)

	c.advanceTime(24 * time.Hour)

	// Send trajectory, verify the last active timestamp;
	require.NoError(t, c.agentClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
		AgentName: agentName,
		JobID:     pollResp.ID,
		Span: &trajectory.Span{
			Seq:     0,
			Type:    trajectory.SpanFlow,
			Name:    string(ai.WorkflowRepro),
			Started: c.mockedTime,
		},
	}))

	agent, err = aidb.LoadAgent(c.ctx, agentName)
	require.NoError(t, err)
	require.WithinDuration(t, c.mockedTime, agent.LastActive, 30*time.Second)
}

const (
	testAgentRestart = "test-agent-restarts"
	testAgentStalled = "test-agent-stalled"
	testAgentFresh   = "test-agent-fresh"
)

func TestAIAgentRestart(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    testAgentRestart,
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowRepro, Name: string(ai.WorkflowRepro)},
		},
	}

	// Poll first to register the workflow in the Agents table.
	c.agentClient.AIJobPoll(pollReq)

	jobID := c.createAIJob(extID, string(ai.WorkflowRepro), "")
	c.advanceTime(1 * time.Hour)

	pollResp1, _ := c.agentClient.AIJobPoll(pollReq)
	require.Equal(t, pollResp1.ID, jobID)

	// Emulate agent restart.

	c.advanceTime(1 * time.Hour)
	pollResp2, _ := c.agentClient.AIJobPoll(pollReq)
	require.NotEqual(t, pollResp2.ID, "")
	require.NotEqual(t, pollResp2.ID, pollResp1.ID)
	require.Equal(t, pollResp1.Workflow, pollResp2.Workflow)
	require.Equal(t, pollResp1.Args, pollResp2.Args)

	job1, err := aidb.LoadJob(c.ctx, pollResp1.ID)
	require.NoError(t, err)
	require.True(t, job1.Finished.Valid)
	require.Contains(t, job1.Error, "restarted")
}

func TestAIAgentJobOvertake(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrash(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    testAgentStalled,
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowRepro, Name: string(ai.WorkflowRepro)},
		},
	}

	// Poll first to register the workflow in the Agents table.
	c.agentClient.AIJobPoll(pollReq)

	jobID := c.createAIJob(extID, string(ai.WorkflowRepro), "")
	c.advanceTime(1 * time.Hour)

	// Too early to give the job to another agent.
	pollResp1, _ := c.agentClient.AIJobPoll(pollReq)
	require.Equal(t, pollResp1.ID, jobID)

	pollReqFresh := &dashapi.AIJobPollReq{
		AgentName:    testAgentFresh,
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowRepro, Name: string(ai.WorkflowRepro)},
		},
	}

	c.advanceTime(1 * time.Hour)
	pollRespFresh, _ := c.agentClient.AIJobPoll(pollReqFresh)
	require.Equal(t, pollRespFresh.ID, "")

	c.advanceTime(8 * time.Hour)

	// An agent requesting a different workflow should not get the stale repro job.
	pollReqPatching := &dashapi.AIJobPollReq{
		AgentName:    testAgentFresh,
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: string(ai.WorkflowPatching)},
		},
	}
	pollRespPatching, _ := c.agentClient.AIJobPoll(pollReqPatching)
	require.Equal(t, pollRespPatching.ID, "")

	// But if workflow matches, it should get the job.
	pollRespFreshOvertake, _ := c.agentClient.AIJobPoll(pollReqFresh)
	require.NotEqual(t, pollRespFreshOvertake.ID, "")
	require.NotEqual(t, pollRespFreshOvertake.ID, pollResp1.ID)

	job1, err := aidb.LoadJob(c.ctx, pollResp1.ID)
	require.NoError(t, err)
	require.True(t, job1.Finished.Valid)
	require.Contains(t, job1.Error, "inactive")

	job2, err := aidb.LoadJob(c.ctx, pollRespFreshOvertake.ID)
	require.NoError(t, err)
	require.True(t, job2.Started.Valid)
	require.False(t, job2.Finished.Valid)
	require.Equal(t, job2.Error, "")
}

func TestCompactAIJobs(t *testing.T) {
	now := time.Now()
	jobs := []*aidb.Job{
		{ID: "1", Workflow: "W1", Created: now.Add(-1 * time.Hour), Aborted: true},
		{ID: "2", Workflow: "W1", Created: now.Add(-2 * time.Hour), Aborted: false},
		{ID: "3", Workflow: "W2", Created: now.Add(-3 * time.Hour), Aborted: true},
		{ID: "4", Workflow: "W2", Created: now.Add(-4 * time.Hour), Aborted: true},
		{ID: "5", Workflow: "W3", Created: now.Add(-5 * time.Hour), Aborted: true},
	}

	got := compactAIJobs(jobs)
	require.Len(t, got, 4)
	assert.Equal(t, "1", got[0].ID)
	assert.Equal(t, "2", got[1].ID)
	assert.Equal(t, "3", got[2].ID)
	assert.Equal(t, "5", got[3].ID)
}

func TestAIJobNamespaces(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	// Add a restricted client to config via transformContext.
	c.transformContext = func(ctx context.Context) context.Context {
		cfg := *getConfig(ctx)
		newClients := map[string]APIClient{}
		for k, v := range cfg.Clients {
			newClients[k] = v
		}
		newClients["restricted-ai"] = APIClient{
			Key:             "restrictedkey123456",
			Methods:         AIMethods,
			AIJobNamespaces: []string{"ains"}, // Only allow "ains"
		}
		cfg.Clients = newClients
		return contextWithConfig(ctx, &cfg)
	}

	restrictedClient := c.makeClient("restricted-ai", "restrictedkey123456", false)
	unrestrictedClient := c.makeClient("unrestricted-ai", "unrestrictedkey1234", false)

	// Create a job in access-public namespace (which restricted client should NOT see).
	jobIDPublic, err := aidb.CreateJob(c.ctx, &aidb.Job{
		Type:      ai.WorkflowRepro,
		Workflow:  string(ai.WorkflowRepro),
		Namespace: "access-public",
	})
	require.NoError(t, err)

	pollReq := &dashapi.AIJobPollReq{
		AgentName:    "restricted-agent",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowRepro, Name: string(ai.WorkflowRepro)},
		},
	}

	// Poll should NOT return the job for access-public because the client is restricted to ains.
	pollResp1, err := restrictedClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.NotEqual(t, jobIDPublic, pollResp1.ID)

	// Unrestricted client should get the job.
	pollRespGlobal, err := unrestrictedClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, jobIDPublic, pollRespGlobal.ID)

	// Create a job for ains (which restricted client CAN see).
	jobIDAins, err := aidb.CreateJob(c.ctx, &aidb.Job{
		Type:      ai.WorkflowRepro,
		Workflow:  string(ai.WorkflowRepro),
		Namespace: "ains",
	})
	require.NoError(t, err)

	pollResp2, err := restrictedClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, jobIDAins, pollResp2.ID)

	// Unrestricted client should also be able to see jobs in ains.
	jobIDAins2, err := aidb.CreateJob(c.ctx, &aidb.Job{
		Type:      ai.WorkflowRepro,
		Workflow:  string(ai.WorkflowRepro),
		Namespace: "ains",
	})
	require.NoError(t, err)

	pollResp3, err := unrestrictedClient.AIJobPoll(pollReq)
	require.NoError(t, err)
	require.Equal(t, jobIDAins2, pollResp3.ID)

	// Verify trajectory log upload.
	err = restrictedClient.AITrajectoryLog(&dashapi.AITrajectoryReq{JobID: jobIDPublic, Span: &trajectory.Span{}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized")

	err = restrictedClient.AITrajectoryLog(&dashapi.AITrajectoryReq{JobID: jobIDAins, Span: &trajectory.Span{}})
	require.NoError(t, err)

	// .. and job completion.
	err = restrictedClient.AIJobDone(&dashapi.AIJobDoneReq{ID: jobIDPublic})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized")

	err = restrictedClient.AIJobDone(&dashapi.AIJobDoneReq{ID: jobIDAins})
	require.NoError(t, err)
}

func TestAIManualJobCreate(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	c.SetAIConfig(&AIConfig{})

	build := testBuild(1)
	build.Manager = "manager1"
	_, err := apiUploadBuild(c.ctx, "ains", build)
	require.NoError(t, err)

	_, err = c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{AgentName: "agent-name",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "repro-c", Name: "repro-c"},
		},
	})
	require.NoError(t, err)

	body, err := c.POSTForm("/ains/ai", url.Values{
		"ai-job-create":  []string{"repro-c"},
		"KernelRepo":     []string{""},
		"KernelCommit":   []string{"123456"},
		"BugDescription": []string{"test bug"},
	})
	require.NoError(t, err)
	require.Contains(t, string(body), "Kernel Repo is required")

	body, err = c.POSTForm("/ains/ai", url.Values{
		"ai-job-create":  []string{"repro-c"},
		"KernelRepo":     []string{"https://repo.test"},
		"KernelCommit":   []string{""},
		"BugDescription": []string{"test bug"},
	})
	require.NoError(t, err)

	require.Contains(t, string(body), "Kernel Commit is required")
	body, err = c.POSTForm("/ains/ai", url.Values{
		"ai-job-create":  []string{"repro-c"},
		"KernelRepo":     []string{"https://repo.test"},
		"KernelCommit":   []string{"123456"},
		"BugDescription": []string{"test bug"},
	})
	require.NoError(t, err)
	require.Contains(t, string(body), "either a custom kernel config or a manager is required")

	_, err = c.POSTForm("/ains/ai", url.Values{
		"ai-job-create":  []string{"repro-c"},
		"KernelRepo":     []string{"https://repo.test"},
		"KernelCommit":   []string{"123456"},
		"KernelConfig":   []string{"test config"},
		"BugDescription": []string{"test bug"},
	})
	require.NoError(t, err)

	job, err := c.agentClient.AIJobPoll(&dashapi.AIJobPollReq{
		AgentName:    "agent-name",
		CodeRevision: prog.GitRevision,
		Workflows: []dashapi.AIWorkflow{
			{Type: "repro-c", Name: "repro-c"},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, "", job.ID)
	require.Equal(t, "repro-c", job.Workflow)

	args := job.Args
	require.Equal(t, "test bug", args["BugDescription"])
	require.Equal(t, "https://repo.test", args["KernelRepo"])
	require.Equal(t, "123456", args["KernelCommit"])

	_, err = c.AuthGET(AccessUser, "/ains/ai")
	require.NoError(t, err)

	_, err = c.AuthGET(AccessUser, fmt.Sprintf("/ai_job?id=%v", job.ID))
	require.NoError(t, err)

	// Verify that a public user cannot access the job page.
	_, err = c.AuthGET(AccessPublic, fmt.Sprintf("/ai_job?id=%v", job.ID))
	require.Error(t, err)
	require.Contains(t, err.Error(), "307")
	err = c.agentClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      job.ID,
		Results: map[string]any{"status": "success"},
	})
	require.NoError(t, err)
}
