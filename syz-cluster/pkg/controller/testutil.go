// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package controller

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
)

type EntityIDs struct {
	SeriesID  string
	SessionID string
}

// UploadTestSeries returns a (series ID, session ID) tuple.
func UploadTestSeries(t *testing.T, ctx context.Context,
	client *api.Client, series *api.Series) EntityIDs {
	retSeries, err := client.UploadSeries(ctx, series)
	assert.NoError(t, err)
	retSession, err := client.UploadSession(ctx, &api.NewSession{
		ExtID: series.ExtID,
	})
	assert.NoError(t, err)
	return EntityIDs{
		SeriesID:  retSeries.ID,
		SessionID: retSession.ID,
	}
}

func UploadTestBuild(t *testing.T, ctx context.Context, client *api.Client,
	build *api.Build) *api.UploadBuildResp {
	ret, err := client.UploadBuild(ctx, &api.UploadBuildReq{
		Build:  *build,
		Log:    []byte("build log"),
		Config: []byte("build config"),
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

func DummySeries() *api.Series {
	return &api.Series{
		ExtID: "ext-id",
		Title: "test series name",
		Link:  "http://link/to/series",
		Cc:    []string{"first@user.com", "second@user.com"},
		Patches: []api.SeriesPatch{
			{
				Seq:   1,
				Title: "first patch title",
				Body:  []byte("first content"),
			},
		},
	}
}

func DummyBuild() *api.Build {
	return &api.Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		TreeURL:    "https://git/repo",
		ConfigName: "config",
		CommitHash: "abcd",
		Compiler:   "compiler",
	}
}

func DummyFindings() []*api.NewFinding {
	var findings []*api.NewFinding
	for i := 0; i < 2; i++ {
		findings = append(findings, &api.NewFinding{
			Title:    fmt.Sprintf("finding %d", i),
			TestName: "test",
			Report:   []byte(fmt.Sprintf("report %d", i)),
			Log:      []byte(fmt.Sprintf("log %d", i)),
			SyzRepro: []byte(fmt.Sprintf("log %d", i)),
			CRepro:   []byte(fmt.Sprintf("log %d", i)),
		})
	}
	return findings
}

type SeriesWithFindingIDs struct {
	EntityIDs
	BaseBuildID    string
	PatchedBuildID string
}

func FakeSeriesWithFindings(t *testing.T, ctx context.Context, env *app.AppEnvironment,
	client *api.Client, series *api.Series) SeriesWithFindingIDs {
	ids := UploadTestSeries(t, ctx, client, series)
	baseBuild := UploadTestBuild(t, ctx, client, DummyBuild())
	patchedBuild := UploadTestBuild(t, ctx, client, DummyBuild())
	err := client.UploadTestResult(ctx, &api.TestResult{
		SessionID:      ids.SessionID,
		BaseBuildID:    baseBuild.ID,
		PatchedBuildID: patchedBuild.ID,
		TestName:       "test",
		Result:         api.TestRunning,
	})
	assert.NoError(t, err)

	findings := DummyFindings()
	for _, finding := range findings {
		finding.SessionID = ids.SessionID
		err = client.UploadFinding(ctx, finding)
		assert.NoError(t, err)
	}
	MarkSessionFinished(t, env, ids.SessionID)
	return SeriesWithFindingIDs{
		EntityIDs:      ids,
		BaseBuildID:    baseBuild.ID,
		PatchedBuildID: patchedBuild.ID,
	}
}

func MarkSessionFinished(t *testing.T, env *app.AppEnvironment, sessionID string) {
	repo := db.NewSessionRepository(env.Spanner)
	err := repo.Update(context.Background(), sessionID, func(session *db.Session) error {
		session.SetFinishedAt(time.Now())
		return nil
	})
	assert.NoError(t, err)
}
