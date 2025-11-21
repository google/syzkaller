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
		Moderation: true,
		Link:       env.URLs.Series(ids.SeriesID),
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
		MessageID: "direct-reply-id",
		InReplyTo: reportMessageID,
		Reporter:  api.LKMLReporter,
		Time:      time.Now(),
	})
	assert.NoError(t, err)
	assert.Equal(t, &api.RecordReplyResp{
		New:      true,
		ReportID: reportID,
	}, resp)

	// Reply to the reply.
	replyToReply := &api.RecordReplyReq{
		MessageID: "reply-to-reply-id",
		InReplyTo: "direct-reply-id",
		Reporter:  api.LKMLReporter,
		Time:      time.Now(),
	}
	resp, err = reportClient.RecordReply(ctx, replyToReply)
	assert.NoError(t, err)
	assert.Equal(t, &api.RecordReplyResp{
		New:      true,
		ReportID: reportID,
	}, resp)

	t.Run("dup-report", func(t *testing.T) {
		resp, err := reportClient.RecordReply(ctx, replyToReply)
		assert.NoError(t, err)
		assert.Equal(t, &api.RecordReplyResp{
			New:      false,
			ReportID: reportID,
		}, resp)
	})

	t.Run("unknown-message", func(t *testing.T) {
		resp, err := reportClient.RecordReply(ctx, &api.RecordReplyReq{
			MessageID: "whatever",
			InReplyTo: "unknown-id",
			Reporter:  api.LKMLReporter,
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
