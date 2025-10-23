// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLs(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := controller.DummySeries()
	ids := controller.FakeSeriesWithFindings(t, ctx, env, client, testSeries)

	handler, baseURL := testServer(t, env)
	urlGen := api.NewURLGenerator(baseURL)

	urls := []string{
		baseURL,
		baseURL + "/stats",
		urlGen.Series(ids.SeriesID),
	}
	for _, buildID := range []string{ids.BaseBuildID, ids.PatchedBuildID} {
		urls = append(urls, urlGen.BuildConfig(buildID))
		urls = append(urls, urlGen.BuildLog(buildID))
	}

	findings, err := handler.findingRepo.ListForSession(ctx, ids.SessionID, db.NoLimit)
	require.NoError(t, err)
	for _, finding := range findings {
		urls = append(urls, urlGen.FindingLog(finding.ID))
		urls = append(urls, urlGen.FindingCRepro(finding.ID))
		urls = append(urls, urlGen.FindingSyzRepro(finding.ID))
	}
	for _, url := range urls {
		t.Logf("checking %s", url)
		resp, err := http.Get(url)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"%q was expected to return HTTP 200, body: %s", url, string(body))
	}
}

func TestAllPatches(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := &api.Series{
		ExtID: "ext-id",
		Title: "test series name",
		Link:  "http://link/to/series",
		Patches: []api.SeriesPatch{
			{
				Seq:   1,
				Title: "first patch title",
				Body:  []byte("first content\n"),
			},
			{
				Seq:   2,
				Title: "second patch title",
				Body:  []byte("second content\n"),
			},
		},
	}
	ids := controller.UploadTestSeries(t, ctx, client, testSeries)
	_, baseURL := testServer(t, env)

	resp, err := http.Get(baseURL + "/series/" + ids.SeriesID + "/all_patches")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, "first content\nsecond content\n", string(body))
}

func testServer(t *testing.T, env *app.AppEnvironment) (*dashboardHandler, string) {
	handler, err := newHandler(env)
	require.NoError(t, err)
	server := httptest.NewServer(handler.Mux())
	t.Cleanup(server.Close)
	return handler, server.URL
}
