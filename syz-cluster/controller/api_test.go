// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
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
	repo := db.NewSeriesRepository(env.Spanner)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	series := addTestSeries(t, repo, env.BlobStorage)
	client := api.NewClient(server.URL)
	ret, err := client.GetSeries(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, testSeriesReply, ret)
}

func TestAPISuccessfulBuild(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	apiServer := NewControllerAPI(env)
	server := httptest.NewServer(apiServer.Mux())
	defer server.Close()

	buildInfo := &api.Build{
		Arch:         "amd64",
		TreeName:     "mainline",
		ConfigName:   "config",
		CommitHash:   "abcd",
		CommitDate:   time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		BuildSuccess: true,
	}
	client := api.NewClient(server.URL)
	ret, err := client.UploadBuild(ctx, &api.UploadBuildReq{
		Build: *buildInfo,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, ret.ID)
	info, err := client.LastSuccessfulBuild(ctx, &api.LastBuildReq{
		Arch:       buildInfo.Arch,
		TreeName:   buildInfo.TreeName,
		ConfigName: buildInfo.ConfigName,
	})
	assert.NoError(t, err)
	assert.Equal(t, buildInfo, info)
}
