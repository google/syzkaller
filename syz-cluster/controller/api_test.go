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
	"github.com/stretchr/testify/assert"
)

func TestAPIGetSeries(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	client := api.NewClient(server.URL)
	seriesID, sessionID := uploadSeries(t, ctx, client, testSeries)

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

	client := api.NewClient(server.URL)

	_, sessionID := uploadSeries(t, ctx, client, testSeries)
	_, buildResp := uploadTestBuild(t, client)
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:   sessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test",
		Result:      api.TestRunning,
		Log:         []byte("some log"),
	})
	assert.NoError(t, err)

	t.Run("not existing test", func(t *testing.T) {
		err = client.UploadFinding(ctx, &api.Finding{
			SessionID: sessionID,
			TestName:  "unknown test",
		})
		assert.Error(t, err)
	})

	t.Run("must succeed", func(t *testing.T) {
		finding := &api.Finding{
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

// Returns a (session ID, series ID) tuple.
func uploadSeries(t *testing.T, ctx context.Context, client *api.Client, series *api.Series) (string, string) {
	retSeries, err := client.UploadSeries(ctx, series)
	assert.NoError(t, err)
	retSession, err := client.UploadSession(ctx, &api.NewSession{
		ExtID: series.ExtID,
	})
	assert.NoError(t, err)
	return retSeries.ID, retSession.ID
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
