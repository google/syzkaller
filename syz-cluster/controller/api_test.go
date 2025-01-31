// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestAPIGetSeries(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	series := addTestSeries(t, db.NewSeriesRepository(env.Spanner), env.BlobStorage)
	session := addTestSession(t, db.NewSessionRepository(env.Spanner), series)

	client := api.NewClient(server.URL)
	ret, err := client.GetSessionSeries(ctx, session.ID)
	assert.NoError(t, err)
	assert.Equal(t, testSeriesReply, ret)

	ret, err = client.GetSeries(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, testSeriesReply, ret)
}

func TestAPISuccessfulBuild(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	client := api.NewClient(server.URL)
	buildInfo, _ := uploadTestBuild(t, client)
	info, err := client.LastSuccessfulBuild(ctx, &api.LastBuildReq{
		Arch:       buildInfo.Arch,
		TreeName:   buildInfo.TreeName,
		ConfigName: buildInfo.ConfigName,
	})
	assert.NoError(t, err)
	assert.Equal(t, buildInfo, info)
}

func TestAPISaveFinding(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	series := addTestSeries(t, db.NewSeriesRepository(env.Spanner), env.BlobStorage)
	session := addTestSession(t, db.NewSessionRepository(env.Spanner), series)

	client := api.NewClient(server.URL)
	_, buildResp := uploadTestBuild(t, client)
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:   session.ID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)

	t.Run("not existing test", func(t *testing.T) {
		err = client.UploadFinding(ctx, &api.Finding{
			SessionID: session.ID,
			TestName:  "unknown test",
		})
		assert.Error(t, err)
	})

	t.Run("must succeed", func(t *testing.T) {
		finding := &api.Finding{
			SessionID: session.ID,
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

func uploadTestBuild(t *testing.T, client *api.Client) (*api.Build, *api.UploadBuildResp) {
	buildInfo := &api.Build{
		Arch:         "amd64",
		TreeName:     "mainline",
		ConfigName:   "config",
		CommitHash:   "abcd",
		CommitDate:   time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		BuildSuccess: true,
	}
	ret, err := client.UploadBuild(context.Background(), &api.UploadBuildReq{
		Build: *buildInfo,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, ret.ID)
	return buildInfo, ret
}
