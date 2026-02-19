// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reporter

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeduplicationInReport(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	series := controller.DummySeries()

	_, err := client.UploadSeries(ctx, series)
	require.NoError(t, err)

	ulSession, err := client.UploadSession(ctx, &api.NewSession{
		ExtID: series.ExtID,
	})
	require.NoError(t, err)
	sessionID := ulSession.ID

	build := controller.DummyBuild()
	ulBuild, err := client.UploadBuild(ctx, &api.UploadBuildReq{
		Build: *build,
	})
	require.NoError(t, err)
	buildID := ulBuild.ID

	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      sessionID,
		TestName:       "step-1",
		PatchedBuildID: buildID,
		BaseBuildID:    buildID,
		Result:         api.TestPassed,
	})
	require.NoError(t, err)

	err = client.UploadFinding(ctx, &api.RawFinding{
		SessionID: sessionID,
		TestName:  "step-1",
		Title:     "duplicate-title",
		Log:       []byte("log1"),
		Report:    []byte("report1"),
	})
	require.NoError(t, err)

	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      sessionID,
		TestName:       "step-2",
		PatchedBuildID: buildID,
		BaseBuildID:    buildID,
		Result:         api.TestPassed,
	})
	require.NoError(t, err)

	err = client.UploadFinding(ctx, &api.RawFinding{
		SessionID: sessionID,
		TestName:  "step-2",
		Title:     "duplicate-title",
		Log:       []byte("log2"),
		Report:    []byte("report2"),
	})
	require.NoError(t, err)

	controller.MarkSessionFinished(t, env, sessionID)

	generator := NewGenerator(env)
	err = generator.Process(ctx, 1)
	require.NoError(t, err)

	reportClient := TestServer(t, env)
	nextResp, err := reportClient.GetNextReport(ctx, api.LKMLReporter)
	require.NoError(t, err)
	require.NotNil(t, nextResp.Report)

	require.Len(t, nextResp.Report.Findings, 1)
	f := nextResp.Report.Findings[0]
	assert.Equal(t, "duplicate-title", f.Title)
	assert.Equal(t, "report1", f.Report)
	require.NoError(t, reportClient.ConfirmReport(ctx, nextResp.Report.ID))
}
