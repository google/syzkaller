// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats_test

import (
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorker(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	seriesRepo := db.NewSeriesRepository(env.Spanner)
	seriesStatsRepo := db.NewSeriesStatsRepository(env.Spanner)
	statsRepo := db.NewStatsRepository(env.Spanner)
	findingRepo := db.NewFindingRepository(env.Spanner)

	worker := stats.NewWorker(seriesRepo, seriesStatsRepo, statsRepo, time.Minute)

	setupSeries := func(extID string, version int) controller.SeriesWithFindingIDs {
		series := controller.DummySeries()
		series.ExtID = extID
		series.Version = version
		series.PublishedAt = time.Now()
		data := controller.FakeSeriesWithFindings(t, ctx, env, client, series)
		return data
	}

	dataV1 := setupSeries("ext-id-1", 1)
	findingsV1, err := findingRepo.ListForSession(ctx, dataV1.SessionID, 0)
	require.NoError(t, err)

	require.NoError(t, client.UploadTestStep(ctx, dataV1.SessionID, &api.SessionTestStep{
		TestName:  "test",
		Title:     findingsV1[0].Title,
		FindingID: findingsV1[0].ID,
		Target:    api.StepTargetPatched,
		Result:    api.StepResultPassed,
	}))

	stat1, err := seriesStatsRepo.GetByID(ctx, dataV1.SeriesID)
	require.NoError(t, err)
	assert.Nil(t, stat1)

	worker.RunOnce(ctx)

	stat1, err = seriesStatsRepo.GetByID(ctx, dataV1.SeriesID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stat1.PreventedBugs)

	// Add a second version of the same series and check whether the stats are updated correctly.
	dataV2 := setupSeries("ext-id-2", 2)
	findingsV2, err := findingRepo.ListForSession(ctx, dataV2.SessionID, 0)
	require.NoError(t, err)

	require.NoError(t, client.UploadTestStep(ctx, dataV2.SessionID, &api.SessionTestStep{
		TestName:  "test",
		Title:     findingsV2[0].Title,
		FindingID: findingsV2[0].ID,
		Target:    api.StepTargetPatched,
		Result:    api.StepResultPassed,
	}))
	require.NoError(t, client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      dataV2.SessionID,
		TestName:       "test2",
		Result:         api.TestPassed,
		PatchedBuildID: dataV2.PatchedBuildID,
		Log:            []byte("log"),
	}))
	require.NoError(t, client.UploadTestStep(ctx, dataV2.SessionID, &api.SessionTestStep{
		TestName:  "test2",
		Title:     findingsV2[0].Title,
		FindingID: findingsV2[0].ID,
		Target:    api.StepTargetPatched,
		Result:    api.StepResultPassed,
	}))

	stat2, err := seriesStatsRepo.GetByID(ctx, dataV2.SeriesID)
	require.NoError(t, err)
	assert.Nil(t, stat2)

	worker.RunOnce(ctx)

	stat1, err = seriesStatsRepo.GetByID(ctx, dataV1.SeriesID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), stat1.PreventedBugs)

	stat2, err = seriesStatsRepo.GetByID(ctx, dataV2.SeriesID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stat2.PreventedBugs)

	stats, err := statsRepo.PreventedBugsPerMonth(ctx)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, int64(1), stats[0].Series)
	assert.Equal(t, int64(1), stats[0].Bugs)
}
