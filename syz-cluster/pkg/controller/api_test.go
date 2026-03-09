// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package controller

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIGetSeries(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	ids := UploadTestSeries(t, ctx, client, testSeries)

	ret, err := client.GetSessionSeries(ctx, ids.SessionID)
	assert.NoError(t, err)
	ret.ID = ""
	assert.Equal(t, testSeries, ret)

	ret, err = client.GetSeries(ctx, ids.SeriesID)
	assert.NoError(t, err)
	ret.ID = ""
	assert.Equal(t, testSeries, ret)
}

func TestAPISuccessfulBuild(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	UploadTestBuild(t, ctx, client, testBuild)
	info, err := client.LastBuild(ctx, &api.LastBuildReq{
		Arch:       testBuild.Arch,
		TreeName:   testBuild.TreeName,
		ConfigName: testBuild.ConfigName,
		Status:     api.BuildSuccess,
	})
	assert.NoError(t, err)
	assert.Equal(t, testBuild, info)
}

func TestAPISaveFinding(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)

	ids := UploadTestSeries(t, ctx, client, testSeries)
	buildResp := UploadTestBuild(t, ctx, client, testBuild)
	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)

	t.Run("not existing test", func(t *testing.T) {
		err = client.UploadFinding(ctx, &api.RawFinding{
			SessionID: ids.SessionID,
			TestName:  "unknown test",
		})
		assert.Error(t, err)
	})

	t.Run("must succeed", func(t *testing.T) {
		finding := &api.RawFinding{
			SessionID:    ids.SessionID,
			TestName:     "test",
			Title:        "title",
			Report:       []byte("report"),
			Log:          []byte("log"),
			SyzRepro:     []byte("syz repro"),
			SyzReproOpts: []byte("syz_repro_opts"),
		}
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
		// Even if the same finding is reported the second time, it must still not fail.
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
	})

	t.Run("add C repro", func(t *testing.T) {
		finding := &api.RawFinding{
			SessionID:    ids.SessionID,
			TestName:     "test",
			Title:        "title",
			Report:       []byte("report"),
			Log:          []byte("log"),
			SyzRepro:     []byte("syz repro"),
			SyzReproOpts: []byte("syz_repro_opts"),
			CRepro:       []byte("C repro"),
		}
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
		// Verify that C repro has appeared indeed.
		findingRepo := db.NewFindingRepository(env.Spanner)
		findings, err := findingRepo.ListForSession(ctx, ids.SessionID, db.NoLimit)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.NotEmpty(t, findings[0].CReproURI)
	})

	t.Run("session stopped", func(t *testing.T) {
		MarkSessionFinished(t, env, ids.SessionID)
		finding := &api.RawFinding{
			SessionID: ids.SessionID,
			TestName:  "test",
			Title:     "new title",
			Report:    []byte("report"),
			Log:       []byte("log"),
			SyzRepro:  []byte("syz repro"),
		}
		err = client.UploadFinding(ctx, finding)
		assert.ErrorContains(t, err, "session is already finished")
	})
}

func TestAPIUploadTestArtifacts(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)

	ids := UploadTestSeries(t, ctx, client, testSeries)
	buildResp := UploadTestBuild(t, ctx, client, testBuild)
	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)
	err = client.UploadTestArtifacts(ctx, ids.SessionID, "test", bytes.NewReader([]byte("artifacts content")))
	assert.NoError(t, err)
}

func TestAPIBaseFindings(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	buildResp := UploadTestBuild(t, ctx, client, testBuild)

	err := client.UploadBaseFinding(ctx, &api.BaseFindingInfo{
		BuildID: buildResp.ID,
		Title:   "title 1",
	})
	assert.NoError(t, err)

	// Let's upload a different build for the same revision.
	buildResp2 := UploadTestBuild(t, ctx, client, testBuild)
	assert.NotEqual(t, buildResp.ID, buildResp2.ID)

	resp, err := client.BaseFindingStatus(ctx, &api.BaseFindingInfo{
		BuildID: buildResp2.ID,
		Title:   "title 1",
	})
	assert.NoError(t, err)
	assert.True(t, resp.Observed)

	t.Run("unseen title", func(t *testing.T) {
		resp, err := client.BaseFindingStatus(ctx, &api.BaseFindingInfo{
			BuildID: buildResp2.ID,
			Title:   "title 2",
		})
		assert.NoError(t, err)
		assert.False(t, resp.Observed)
	})

	t.Run("invalid build id", func(t *testing.T) {
		_, err := client.BaseFindingStatus(ctx, &api.BaseFindingInfo{
			BuildID: "unknown id",
			Title:   "title 1",
		})
		assert.Error(t, err)
	})
}

var testSeries = &api.Series{
	ExtID:       "ext-id",
	AuthorEmail: "some@email.com",
	Title:       "test series name",
	Version:     2,
	PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
	Cc:          []string{"email"},
	SubjectTags: []string{"tag"},
	Patches: []api.SeriesPatch{
		{
			Seq:  1,
			Body: []byte("first content"),
		},
		{
			Seq:  2,
			Body: []byte("second content"),
		},
	},
}

var testBuild = &api.Build{
	Arch:         "amd64",
	TreeName:     "mainline",
	TreeURL:      "https://git/tree",
	ConfigName:   "config",
	CommitHash:   "abcd",
	CommitDate:   time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
	BuildSuccess: true,
}

func TestAPIListPreviousFindings(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)

	// Setup v1 Series.
	// It has "Crash in foo" and "Crash in bar".
	seriesV1 := DummySeries()
	seriesV1.Version = 1
	seriesV1.ExtID = "ext-id-1"
	idsV1 := UploadTestSeries(t, ctx, client, seriesV1)

	buildV1 := DummyBuild()
	buildV1.ConfigName = "config-1"
	buildV1Resp := UploadTestBuild(t, ctx, client, buildV1)

	require.NoError(t, client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      idsV1.SessionID,
		TestName:       "test",
		Result:         api.TestPassed,
		PatchedBuildID: buildV1Resp.ID,
		Log:            []byte("log"),
	}))

	require.NoError(t, client.UploadFinding(ctx, &api.RawFinding{
		SessionID: idsV1.SessionID,
		Title:     "Crash in foo",
		TestName:  "test",
		SyzRepro:  []byte("syz repro"),
	}))
	require.NoError(t, client.UploadFinding(ctx, &api.RawFinding{
		SessionID: idsV1.SessionID,
		Title:     "Crash in bar",
		TestName:  "test",
		SyzRepro:  []byte("syz repro"),
	}))
	require.NoError(t, client.UploadFinding(ctx, &api.RawFinding{
		SessionID: idsV1.SessionID,
		Title:     "Build error without repro",
		TestName:  "test",
	}))
	MarkSessionFinished(t, env, idsV1.SessionID)

	// Setup v2 Series.
	seriesV2 := DummySeries()
	seriesV2.Version = 2
	seriesV2.ExtID = "ext-id-2"
	idsV2 := UploadTestSeries(t, ctx, client, seriesV2)

	buildV2 := DummyBuild()
	buildV2.ConfigName = "config-1"
	buildV2Resp := UploadTestBuild(t, ctx, client, buildV2)

	require.NoError(t, client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      idsV2.SessionID,
		TestName:       "test",
		Result:         api.TestPassed,
		PatchedBuildID: buildV2Resp.ID,
		Log:            []byte("log"),
	}))

	require.NoError(t, client.UploadFinding(ctx, &api.RawFinding{
		SessionID: idsV2.SessionID,
		Title:     "Crash in foo",
		TestName:  "test",
		SyzRepro:  []byte("syz repro"),
	}))
	MarkSessionFinished(t, env, idsV2.SessionID)

	// Setup v3 Series.
	seriesV3 := DummySeries()
	seriesV3.Version = 3
	seriesV3.ExtID = "ext-id-3"
	idsV3 := UploadTestSeries(t, ctx, client, seriesV3)

	list, err := client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
		SeriesID: idsV3.SeriesID,
	})
	require.NoError(t, err)
	require.Len(t, list, 2)

	finding1, err := client.GetFinding(ctx, list[0])
	require.NoError(t, err)
	assert.Equal(t, "Crash in bar", finding1.Title)
	assert.Equal(t, idsV1.SessionID, finding1.SessionID)

	finding2, err := client.GetFinding(ctx, list[1])
	require.NoError(t, err)
	assert.Equal(t, "Crash in foo", finding2.Title)
	assert.Equal(t, idsV1.SessionID, finding2.SessionID)

	list, err = client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
		SeriesID: idsV3.SeriesID,
		Arch:     buildV1.Arch,
		Config:   buildV1.ConfigName,
	})
	require.NoError(t, err)
	require.Len(t, list, 2)

	list, err = client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
		SeriesID: idsV3.SeriesID,
		Arch:     "wrong-arch",
		Config:   buildV1.ConfigName,
	})
	require.NoError(t, err)
	require.Empty(t, list)

	list, err = client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
		SeriesID: idsV2.SeriesID,
		Arch:     buildV1.Arch,
		Config:   "wrong-config",
	})
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestAPIGetFinding(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	ids := UploadTestSeries(t, ctx, client, testSeries)
	buildResp := UploadTestBuild(t, ctx, client, testBuild)
	require.NoError(t, client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
	}))

	finding := &api.RawFinding{
		SessionID:    ids.SessionID,
		TestName:     "test",
		Title:        "title",
		SyzRepro:     []byte("syz repro"),
		SyzReproOpts: []byte("syz repro opts"),
		CRepro:       []byte("c repro"),
	}
	require.NoError(t, client.UploadFinding(ctx, finding))

	findingRepo := db.NewFindingRepository(env.Spanner)
	findings, err := findingRepo.ListForSession(ctx, ids.SessionID, 0)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	findingID := findings[0].ID

	resp, err := client.GetFinding(ctx, findingID)
	require.NoError(t, err)
	assert.Equal(t, finding.Title, resp.Title)
	assert.Equal(t, finding.SyzRepro, resp.SyzRepro)
	assert.Equal(t, finding.SyzReproOpts, resp.SyzReproOpts)
	assert.Equal(t, finding.SyzReproOpts, resp.SyzReproOpts)
	assert.Equal(t, finding.CRepro, resp.CRepro)

	_, err = client.GetFinding(ctx, "unknown-id")
	assert.Error(t, err)
}

func TestAPIUploadTestStep(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	ids := UploadTestSeries(t, ctx, client, testSeries)

	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID: ids.SessionID,
		TestName:  "test",
		Result:    api.TestRunning,
	})
	require.NoError(t, err)

	err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
		TestName:  "test",
		FindingID: "",
		Target:    api.StepTargetPatched,
		Title:     "some title",
		Log:       []byte("log"),
		Result:    api.StepResultPassed,
	})
	require.NoError(t, err)

	repo := db.NewSessionTestStepRepository(env.Spanner)
	steps, err := repo.ListForSession(ctx, ids.SessionID, "test")
	require.NoError(t, err)
	require.Len(t, steps, 1)

	// Overwrite the step.
	err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
		TestName:  "test",
		FindingID: "",
		Target:    api.StepTargetPatched,
		Title:     "some title",
		Result:    api.StepResultFailed,
	})
	require.NoError(t, err)

	steps, err = repo.ListForSession(ctx, ids.SessionID, "test")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, api.StepResultFailed, steps[0].Result)
}

func TestAPIGetTrees(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)

	resp, err := client.GetTrees(ctx)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, env.Config.Trees, resp.Trees)
	assert.Equal(t, env.Config.FuzzTargets, resp.FuzzTargets)
}

func TestAPISubmitJob(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	ids := UploadTestSeries(t, ctx, client, testSeries)
	report := UploadTestSessionReport(t, env, ids.SessionID)

	req := &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  report.ID,
		Reporter:  "test-reporter",
		User:      "user@example.com",
		ExtID:     "msg-id-123",
		PatchData: []byte("patch content"),
	}

	resp, err := client.SubmitJob(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.JobID)

	_, err = client.SubmitJob(ctx, req)
	// Job already exists.
	assert.Error(t, err)
}

func TestAPIGetSessionInfo(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	ids := UploadTestSeries(t, ctx, client, testSeries)

	baseBuild := UploadTestBuild(t, ctx, client, DummyBuild())
	patchedBuild := UploadTestBuild(t, ctx, client, DummyBuild())
	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      ids.SessionID,
		BaseBuildID:    baseBuild.ID,
		PatchedBuildID: patchedBuild.ID,
		TestName:       "test",
		Result:         api.TestRunning,
	})
	require.NoError(t, err)

	findings := DummyFindings()
	for _, finding := range findings {
		finding.SessionID = ids.SessionID
		err = client.UploadFinding(ctx, finding)
		require.NoError(t, err)
	}

	// Add a second distinct build test to the original session.
	build2 := DummyBuild()
	build2.ConfigName = "config2"
	pb2 := UploadTestBuild(t, ctx, client, build2)
	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      ids.SessionID,
		BaseBuildID:    pb2.ID,
		PatchedBuildID: pb2.ID,
		TestName:       "test-2",
		Result:         api.TestRunning,
	})
	require.NoError(t, err)

	finding2 := &api.RawFinding{
		SessionID:    ids.SessionID,
		TestName:     "test-2",
		Title:        "second finding",
		Report:       []byte("report 2"),
		Log:          []byte("log 2"),
		SyzRepro:     []byte("syz repro 2"),
		SyzReproOpts: []byte("syz_repro_opts 2"),
	}
	err = client.UploadFinding(ctx, finding2)
	require.NoError(t, err)

	MarkSessionFinished(t, env, ids.SessionID)

	// Test without job.
	info, err := client.GetSessionInfo(ctx, ids.SessionID)
	require.NoError(t, err)
	assert.NotNil(t, info.Series)
	assert.Nil(t, info.Job)
	assert.Equal(t, testSeries.Title, info.Series.Title)

	report := UploadTestSessionReport(t, env, ids.SessionID)

	resp, err := client.SubmitJob(ctx, &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  report.ID,
		Reporter:  api.LKMLReporter,
		User:      "test-user@vger.kernel.org",
		ExtID:     "test-message-id",
		PatchData: []byte("patch content"),
	})
	require.NoError(t, err)

	sessionID := FakeJobSession(t, env, client, resp.SessionID)

	// Test with a job.
	info, err = client.GetSessionInfo(ctx, sessionID)
	require.NoError(t, err)
	assert.NotNil(t, info.Series)
	assert.NotNil(t, info.Job)
	assert.Equal(t, report.ID, info.Job.ReportID)
	assert.Len(t, info.Job.FindingGroups, 2)
	assert.Len(t, info.Job.FindingGroups[1].FindingIDs, 2)
	assert.Equal(t, api.Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		TreeURL:    "https://git/repo",
		ConfigName: "config",
		CommitHash: "abcd",
	}, info.Job.FindingGroups[1].Build)
	assert.Len(t, info.Job.FindingGroups[0].FindingIDs, 1)
	assert.Equal(t, api.Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		TreeURL:    "https://git/repo",
		ConfigName: "config2",
		CommitHash: "abcd",
	}, info.Job.FindingGroups[0].Build)
}
