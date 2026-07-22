// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeriesStatsOutdated(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesStatsRepository(client)
	seriesRepo := NewSeriesRepository(client)
	dtd := &dummyTestData{t: t, ctx: ctx, client: client}
	series1 := dtd.dummySeries()

	series2 := &Series{ExtID: "series-ext-id-2"}
	err := seriesRepo.Insert(ctx, series2, nil)
	require.NoError(t, err)

	session2 := dtd.dummySession(series2)
	dtd.setLatestSession(series2, session2)

	session1 := dtd.dummySession(series1)
	dtd.setLatestSession(series1, session1)

	dtd.startSession(session1)
	dtd.finishSession(session1)

	list, err := repo.ListOutdated(ctx, ListOutdatedFilter{Limit: 10, CurrentVersion: "v2"})
	require.NoError(t, err)
	// Session2 is not yet finished.
	require.Len(t, list, 1)
	require.Equal(t, series1.ID, list[0].ID)
}

func TestSeriesStatsBulkUpdateMissing(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesStatsRepository(client)
	seriesRepo := NewSeriesRepository(client)
	series1 := &Series{ExtID: "ext-missing-1"}
	series2 := &Series{ExtID: "ext-missing-2"}
	require.NoError(t, seriesRepo.Insert(ctx, series1, nil))
	require.NoError(t, seriesRepo.Insert(ctx, series2, nil))

	require.NoError(t, repo.Upsert(ctx, &SeriesStats{ID: series1.ID, PreventedBugs: 1}))

	ids := []string{series1.ID, series2.ID}
	err := repo.BulkUpdate(ctx, ids, func(s *SeriesStats) {
		s.PreventedBugs = 5
	})
	require.NoError(t, err)

	stat1, err := repo.GetByID(ctx, series1.ID)
	require.NoError(t, err)
	require.NotNil(t, stat1)
	require.Equal(t, int64(5), stat1.PreventedBugs)

	stat2, err := repo.GetByID(ctx, series2.ID)
	require.NoError(t, err)
	require.Nil(t, stat2)
}
