// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeriesStatsOutdated(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesStatsRepository(client)
	seriesRepo := NewSeriesRepository(client)
	dtd := &dummyTestData{t: t, ctx: ctx, client: client}
	series1 := dtd.dummySeries()

	series2 := &Series{ExtID: "series-ext-id-2"}
	err := seriesRepo.Insert(ctx, series2, nil)
	assert.NoError(t, err)

	session2 := dtd.dummySession(series2)
	dtd.setLatestSession(series2, session2)

	session1 := dtd.dummySession(series1)
	dtd.setLatestSession(series1, session1)

	dtd.startSession(session1)
	dtd.finishSession(session1)

	list, err := repo.ListOutdated(ctx, ListOutdatedFilter{Limit: 10, CurrentVersion: "v2"})
	assert.NoError(t, err)
	// Session2 is not yet finished.
	assert.Len(t, list, 1)
	assert.Equal(t, series1.ID, list[0].ID)
}
