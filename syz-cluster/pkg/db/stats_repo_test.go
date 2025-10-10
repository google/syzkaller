// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatsSQLs(t *testing.T) {
	// Ideally, there should be some proper tests, but for now let's at least
	// check that the SQL queries themselves have no errors.
	// That already brings a lot of value.
	client, ctx := NewTransientDB(t)

	checkStats := func() {
		statsRepo := NewStatsRepository(client)
		_, err := statsRepo.ProcessedSeriesPerWeek(ctx)
		assert.NoError(t, err)
		_, err = statsRepo.FindingsPerWeek(ctx)
		assert.NoError(t, err)
		_, err = statsRepo.SessionStatusPerWeek(ctx)
		assert.NoError(t, err)
		_, err = statsRepo.DelayPerWeek(ctx)
		assert.NoError(t, err)
		_, err = statsRepo.ReportsPerWeek(ctx)
		assert.NoError(t, err)
	}

	dtd := &dummyTestData{t, ctx, client}
	session := dtd.dummySession(dtd.dummySeries())
	checkStats()
	dtd.startSession(session)
	dtd.addSessionTest(session, "test")
	checkStats()
	dtd.addFinding(session, "test", "test")
	checkStats()
	dtd.finishSession(session)
	checkStats()
}
