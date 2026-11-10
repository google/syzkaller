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
		baseURL + "/stats?unstable_stats=true",
		urlGen.Series(ids.SeriesID),
		baseURL + "/session/" + ids.SessionID,
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

func TestPatchContentType(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	testSeries := &api.Series{
		ExtID: "ext-id",
		Title: "test series name",
		Patches: []api.SeriesPatch{
			{
				Seq:   1,
				Title: "patch title",
				Body:  []byte("<html><script>alert(1)</script>\n"),
			},
		},
	}
	ids := controller.UploadTestSeries(t, ctx, client, testSeries)
	handler, baseURL := testServer(t, env)
	series, err := handler.seriesRepo.GetByID(ctx, ids.SeriesID)
	require.NoError(t, err)
	patches, err := handler.seriesRepo.ListPatches(ctx, series)
	require.NoError(t, err)
	require.Len(t, patches, 1)

	for _, url := range []string{
		baseURL + "/series/" + ids.SeriesID + "/all_patches",
		baseURL + "/patches/" + patches[0].ID,
	} {
		resp, err := http.Get(url)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, url)
		assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"), url)
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"), url)
	}
}

func testServer(t *testing.T, env *app.AppEnvironment) (*dashboardHandler, string) {
	handler, err := newHandler(env)
	require.NoError(t, err)
	server := httptest.NewServer(handler.Mux())
	t.Cleanup(server.Close)
	return handler, server.URL
}
