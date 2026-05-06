// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reporter

import (
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIReportFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)

	// Create series/session/test/findings.
	testSeries := controller.DummySeries()
	ids := controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	assert.NoError(t, err)

	reportClient := TestServer(t, env)
	// The same report will be returned multiple times.
	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	assert.NoError(t, err)
	nextResp2, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	assert.NoError(t, err)
	assert.Equal(t, nextResp2, nextResp)
	// We don't know IDs in advance.
	nextResp.Report.ID = ""
	nextResp.Report.Series.ID = ""
	// For URLs, just check if they are in place.
	for _, finding := range nextResp.Report.Findings {
		assert.NotEmpty(t, finding.LogURL, "%q's LogURL is empty", finding.Title)
		finding.LogURL = ""
		assert.NotEmpty(t, finding.LinkCRepro, "%q's LinkCRepro is empty", finding.Title)
		finding.LinkCRepro = ""
		assert.NotEmpty(t, finding.LinkSyzRepro, "%q's LinkSyzRepro is empty", finding.Title)
		finding.LinkSyzRepro = ""
		assert.NotEmpty(t, finding.Build.ConfigLink, "%q's ConfigLink is empty", finding.Title)
		finding.Build.ConfigLink = ""
	}

	assert.Equal(t, &api.SessionReport{
		Type:       api.ReportTypeBug,
		Moderation: true,
		Link:       env.URLs.Series(ids.SeriesID),
		InReplyTo:  testSeries.ExtID,
		Cc:         []string{"first@user.com", "second@user.com"},
		Series: &api.Series{
			ExtID: testSeries.ExtID,
			Title: testSeries.Title,
			Link:  "http://link/to/series",
			Cc:    []string{"first@user.com", "second@user.com"},
			Patches: []api.SeriesPatch{
				{
					Seq:   1,
					Title: "first patch title",
					// Body is empty.
				},
			},
		},
		// These findings relate to controller.DummyFindings().
		Findings: []*api.Finding{
			{
				Title:  "finding 0",
				Report: "report 0",
				Build: api.BuildInfo{
					TreeName:   "mainline",
					TreeURL:    "https://git/repo",
					BaseCommit: "abcd",
					Arch:       "amd64",
					Compiler:   "compiler",
				},
			},
			{
				Title:  "finding 1",
				Report: "report 1",
				Build: api.BuildInfo{
					TreeName:   "mainline",
					TreeURL:    "https://git/repo",
					BaseCommit: "abcd",
					Arch:       "amd64",
					Compiler:   "compiler",
				},
			},
		},
	}, nextResp.Report)

	// Now confirm it.
	reportID := nextResp2.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	assert.NoError(t, err)

	// It should no longer appear in Next().
	emptyNext, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	assert.NoError(t, err)
	assert.Nil(t, emptyNext.Report)

	// "Upstream" it.
	err = reportClient.UpstreamReport(ctx, reportID, &api.UpstreamReportReq{
		User: "name",
	})
	assert.NoError(t, err)

	// It should appear again, now with Moderation=false.
	nextResp3, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	assert.NoError(t, err)
	assert.False(t, nextResp3.Report.Moderation)
	assert.Equal(t, nextResp2.Report.Series, nextResp3.Report.Series)
}

func TestReplyReporting(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)

	// Create series/session/test/findings.
	testSeries := controller.DummySeries()
	controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	assert.NoError(t, err)

	// Create a report.
	reportClient := TestServer(t, env)
	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	assert.NoError(t, err)

	// Confirm the report and set its message ID.
	reportID := nextResp.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	assert.NoError(t, err)

	const reportMessageID = "message-id"
	_, err = reportClient.RecordReply(ctx, &api.RecordReplyReq{
		MessageID: reportMessageID,
		ReportID:  reportID,
		Reporter:  api.LKMLReporter,
	})
	assert.NoError(t, err)

	// Direct reply to the report.
	resp, err := reportClient.RecordReply(ctx, &api.RecordReplyReq{
		MessageID:     "direct-reply-id",
		RootMessageID: reportMessageID,
		Reporter:      api.LKMLReporter,
		Time:          time.Now(),
	})
	assert.NoError(t, err)
	assert.Equal(t, &api.RecordReplyResp{
		New:      true,
		ReportID: reportID,
	}, resp)

	t.Run("unknown-message", func(t *testing.T) {
		resp, err := reportClient.RecordReply(ctx, &api.RecordReplyReq{
			MessageID:     "whatever",
			RootMessageID: "unknown-id",
			Reporter:      api.LKMLReporter,
		})
		assert.NoError(t, err)
		assert.Equal(t, &api.RecordReplyResp{
			New:      false,
			ReportID: "",
		}, resp)
	})
}

func TestInvalidate(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := controller.DummySeries()
	ids := controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	require.NoError(t, err)

	// Create a report.
	reportClient := TestServer(t, env)
	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)
	reportID := nextResp.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	require.NoError(t, err)

	// Invalidate the findings.
	err = reportClient.InvalidateReport(ctx, reportID)
	require.NoError(t, err)

	// Report should not appear in Next().
	emptyNext, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)
	assert.Nil(t, emptyNext.Report)

	// All findings must be invalidated.
	findingService := service.NewFindingService(env)
	list, err := findingService.List(ctx, ids.SessionID, 0)
	require.NoError(t, err)
	assert.Len(t, list, 2)
	for i, finding := range list {
		assert.True(t, finding.Invalidated, "finding %d must be invalidated", i)
	}
}

func TestPatchTestReporting(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := controller.DummySeries()

	controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	require.NoError(t, err)

	reportClient := TestServer(t, env)

	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)
	require.NotNil(t, nextResp.Report)

	reportID := nextResp.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	require.NoError(t, err)
	assert.Equal(t, testSeries.ExtID, nextResp.Report.InReplyTo)

	submitResp, err := client.SubmitJob(ctx, &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  reportID,
		Reporter:  api.LKMLReporter,
		User:      "test-user@vger.kernel.org",
		ExtID:     "patch-test-message-id",
		PatchData: []byte("patch content"),
	})
	require.NoError(t, err)

	controller.FakeJobSession(t, env, client, submitResp.SessionID)

	err = generator.Process(ctx, 1)
	require.NoError(t, err)

	nextRespPatch, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)
	require.NotNil(t, nextRespPatch.Report)

	patchReport := nextRespPatch.Report
	assert.Equal(t, api.ReportTypePatchTest, patchReport.Type)
	assert.Equal(t, "patch-test-message-id", patchReport.InReplyTo)
	assert.Equal(t, []api.ReportTest{
		{
			Name:   "build",
			Status: api.TestPassed,
		},
		{
			Name:   "run repros",
			Status: api.TestPassed,
			Steps: []api.ReportTestStep{
				{
					Name:   "repro A (patched)",
					Status: api.StepResultPassed,
				},
			},
		},
	}, patchReport.Tests)
}

func TestPatchTestReportingTriageSkip(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := controller.DummySeries()

	controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	require.NoError(t, err)

	reportClient := TestServer(t, env)

	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)

	reportID := nextResp.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	require.NoError(t, err)

	submitResp, err := client.SubmitJob(ctx, &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  reportID,
		Reporter:  api.LKMLReporter,
		User:      "test-user1@vger.kernel.org",
		ExtID:     "patch-test-skipped",
		PatchData: []byte("patch content"),
	})
	require.NoError(t, err)

	skippedSessionID := submitResp.SessionID
	err = client.UploadTriageResult(ctx, skippedSessionID, &api.UploadTriageResultReq{
		SkipReason: "simulated test failure",
	})
	require.NoError(t, err)
	controller.MarkSessionFinished(t, env, skippedSessionID)

	err = generator.Process(ctx, 1)
	require.NoError(t, err)

	nextRespSkipped, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)

	skippedReport := nextRespSkipped.Report
	assert.Equal(t, api.ReportTypePatchTest, skippedReport.Type)
	assert.Equal(t, "simulated test failure", skippedReport.Error)
	assert.Empty(t, skippedReport.Tests)
}

func TestPatchTestReportingFailedStep(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := controller.DummySeries()

	controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	generator := NewGenerator(env)
	err := generator.Process(ctx, 1)
	require.NoError(t, err)

	reportClient := TestServer(t, env)
	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)

	reportID := nextResp.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	require.NoError(t, err)

	submitResp, err := client.SubmitJob(ctx, &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  reportID,
		Reporter:  api.LKMLReporter,
		User:      "test-user2@vger.kernel.org",
		ExtID:     "patch-test-failed-step",
		PatchData: []byte("patch content 2"),
	})
	require.NoError(t, err)

	failedSessionID := submitResp.SessionID

	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID: failedSessionID,
		TestName:  "build",
		Result:    api.TestPassed,
	})
	require.NoError(t, err)

	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID: failedSessionID,
		TestName:  "run repros",
		Result:    api.TestError,
	})
	require.NoError(t, err)

	err = client.UploadTestStep(ctx, failedSessionID, &api.SessionTestStep{
		TestName: "run repros",
		Title:    "repro A",
		Target:   api.StepTargetPatched,
		Result:   api.StepResultError,
	})
	require.NoError(t, err)

	controller.MarkSessionFinished(t, env, failedSessionID)

	err = generator.Process(ctx, 1)
	require.NoError(t, err)

	nextRespFailed, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)

	failedReport := nextRespFailed.Report
	assert.Equal(t, api.ReportTypePatchTest, failedReport.Type)
	assert.Equal(t, "Testing failed due to an infrastructure error.", failedReport.Error)
	assert.Len(t, failedReport.Tests, 2)
}
