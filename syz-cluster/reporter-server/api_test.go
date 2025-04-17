// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
	"github.com/stretchr/testify/assert"
)

func TestAPIReportFlow(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)

	// Create series/session/test/findings.
	_, sessionID := controller.UploadTestSeries(t, ctx, client, testSeries)
	buildResp := controller.UploadTestBuild(t, ctx, client, &api.Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		ConfigName: "config",
		CommitHash: "abcd",
	})
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:   sessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
	})
	assert.NoError(t, err)
	for i := 0; i < 2; i++ {
		finding := &api.NewFinding{
			SessionID: sessionID,
			Title:     fmt.Sprintf("finding %d", i),
			TestName:  "test",
			Report:    []byte(fmt.Sprintf("report %d", i)),
		}
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
	}

	markSessionFinished(t, env, sessionID)

	generator := newReportGenerator(env)
	err = generator.process(ctx, 1)
	assert.NoError(t, err)

	reportClient := ReporterServer(t, env)
	// The same report will be returned multiple times.
	nextResp, err := reportClient.GetNextReport(ctx)
	assert.NoError(t, err)
	nextResp2, err := reportClient.GetNextReport(ctx)
	assert.NoError(t, err)
	assert.Equal(t, nextResp2, nextResp)
	// We don't know IDs in advance.
	nextResp.Report.ID = ""
	nextResp.Report.Series.ID = ""
	assert.Equal(t, &api.SessionReport{
		Moderation: true,
		Series: &api.Series{
			ExtID: testSeries.ExtID,
			Title: testSeries.Title,
			Patches: []api.SeriesPatch{
				{
					Seq:   1,
					Title: "first patch title",
					// Body is empty.
				},
			},
		},
		Findings: []*api.Finding{
			{
				Title:  "finding 0",
				Report: "report 0",
				LogURL: "TODO", // TODO
			},
			{
				Title:  "finding 1",
				Report: "report 1",
				LogURL: "TODO", // TODO
			},
		},
	}, nextResp.Report)

	// Now confirm it.
	reportID := nextResp2.Report.ID
	err = reportClient.ConfirmReport(ctx, reportID)
	assert.NoError(t, err)

	// It should no longer appear in Next().
	emptyNext, err := reportClient.GetNextReport(ctx)
	assert.NoError(t, err)
	assert.Nil(t, emptyNext.Report)

	// "Upstream" it.
	err = reportClient.UpstreamReport(ctx, reportID, &api.UpstreamReportReq{
		User: "name",
	})
	assert.NoError(t, err)

	// It should appear again, now with Moderation=false.
	nextResp3, err := reportClient.GetNextReport(ctx)
	assert.NoError(t, err)
	assert.False(t, nextResp3.Report.Moderation)
	assert.Equal(t, nextResp2.Report.Series, nextResp3.Report.Series)
}

func ReporterServer(t *testing.T, env *app.AppEnvironment) *api.ReporterClient {
	apiServer := NewReporterAPI(service.NewReportService(env))
	server := httptest.NewServer(apiServer.Mux())
	t.Cleanup(server.Close)
	return api.NewReporterClient(server.URL)
}

func markSessionFinished(t *testing.T, env *app.AppEnvironment, sessionID string) {
	repo := db.NewSessionRepository(env.Spanner)
	err := repo.Update(context.Background(), sessionID, func(session *db.Session) error {
		session.SetFinishedAt(time.Now())
		return nil
	})
	assert.NoError(t, err)
}

var testSeries = &api.Series{
	ExtID: "ext-id",
	Title: "test series name",
	Patches: []api.SeriesPatch{
		{
			Seq:   1,
			Title: "first patch title",
			Body:  []byte("first content"),
		},
	},
}
