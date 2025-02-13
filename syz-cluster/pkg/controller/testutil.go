// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package controller

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/stretchr/testify/assert"
)

// UploadTestSeries returns a (session ID, series ID) tuple.
func UploadTestSeries(t *testing.T, ctx context.Context,
	client *api.Client, series *api.Series) (string, string) {
	retSeries, err := client.UploadSeries(ctx, series)
	assert.NoError(t, err)
	retSession, err := client.UploadSession(ctx, &api.NewSession{
		ExtID: series.ExtID,
	})
	assert.NoError(t, err)
	return retSeries.ID, retSession.ID
}

func UploadTestBuild(t *testing.T, ctx context.Context, client *api.Client,
	build *api.Build) *api.UploadBuildResp {
	ret, err := client.UploadBuild(ctx, &api.UploadBuildReq{
		Build: *build,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, ret.ID)
	return ret
}

func TestServer(t *testing.T, env *app.AppEnvironment) *api.Client {
	apiServer := NewAPIServer(env)
	server := httptest.NewServer(apiServer.Mux())
	t.Cleanup(server.Close)
	return api.NewClient(server.URL)
}
