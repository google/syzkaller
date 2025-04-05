// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package controller

import (
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/stretchr/testify/assert"
)

func TestAPIGetSeries(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := TestServer(t, env)
	seriesID, sessionID := UploadTestSeries(t, ctx, client, testSeries)

	ret, err := client.GetSessionSeries(ctx, sessionID)
	assert.NoError(t, err)
	ret.ID = ""
	assert.Equal(t, testSeries, ret)

	ret, err = client.GetSeries(ctx, seriesID)
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

	_, sessionID := UploadTestSeries(t, ctx, client, testSeries)
	buildResp := UploadTestBuild(t, ctx, client, testBuild)
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:   sessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)

	t.Run("not existing test", func(t *testing.T) {
		err = client.UploadFinding(ctx, &api.NewFinding{
			SessionID: sessionID,
			TestName:  "unknown test",
		})
		assert.Error(t, err)
	})

	t.Run("must succeed", func(t *testing.T) {
		finding := &api.NewFinding{
			SessionID: sessionID,
			TestName:  "test",
			Report:    []byte("report"),
			Log:       []byte("log"),
		}
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
		// Even if the finding is reported the second time, it must still not fail.
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
	})
}

var testSeries = &api.Series{
	ExtID:       "ext-id",
	AuthorEmail: "some@email.com",
	Title:       "test series name",
	Version:     2,
	PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
	Cc:          []string{"email"},
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
	ConfigName:   "config",
	CommitHash:   "abcd",
	CommitDate:   time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
	BuildSuccess: true,
}
