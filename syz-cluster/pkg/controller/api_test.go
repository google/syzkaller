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
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)

	t.Run("not existing test", func(t *testing.T) {
		err = client.UploadFinding(ctx, &api.NewFinding{
			SessionID: ids.SessionID,
			TestName:  "unknown test",
		})
		assert.Error(t, err)
	})

	t.Run("must succeed", func(t *testing.T) {
		finding := &api.NewFinding{
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
		finding := &api.NewFinding{
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
		finding := &api.NewFinding{
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
	err := client.UploadTestResult(ctx, &api.TestResult{
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
