// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/stretchr/testify/assert"
)

func TestSeriesInsertSession(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	withSession := func(need int) {
		list, err := seriesRepo.ListLatest(ctx, SeriesFilter{Limit: 10}, time.Time{})
		assert.NoError(t, err)
		var cnt int
		for _, item := range list {
			if item.Session != nil {
				cnt++
			}
		}
		assert.Equal(t, cnt, need)
	}

	// This series is indeed without a session.
	withSession(0)

	// Add a new session.
	session := &Session{SeriesID: series.ID}
	err = sessionRepo.Insert(ctx, session)
	assert.NoError(t, err)

	// The sessions is not started yet.
	withSession(0)

	// Now start it.
	err = sessionRepo.Start(ctx, session.ID)
	assert.NoError(t, err)
	withSession(1)
}

func TestQueryWaitingSessions(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	nthTime := func(i int) time.Time {
		return time.Date(2009, time.January, 1, 1, i, 0, 0, time.UTC)
	}

	for i := range 5 {
		session := &Session{
			SeriesID:  series.ID,
			CreatedAt: nthTime(i),
		}
		err = sessionRepo.Insert(ctx, session)
		assert.NoError(t, err)
	}

	var next *NextSession
	for i := range 5 {
		var list []*Session
		list, next, err = sessionRepo.ListWaiting(ctx, next, 1)
		assert.NoError(t, err)
		assert.Len(t, list, 1)
		assert.Equal(t, nthTime(i), list[0].CreatedAt)
	}
}

func TestJobSessionDoesNotUpdateLatestSession(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)

	dummy := &dummyTestData{t: t, ctx: ctx, client: client}
	series := dummy.dummySeries()
	session1 := dummy.dummySession(series)
	dummy.startSession(session1)

	dbSeries, err := seriesRepo.GetByID(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, session1.ID, dbSeries.LatestSessionID.StringVal)

	report := dummy.dummyReport(session1)

	jobRepo := NewJobRepository(client)
	job := &Job{ID: "job-123", ExtID: "ext-123", ReportID: report.ID, Type: JobPatchTest, Reporter: report.Reporter}
	err = jobRepo.Insert(ctx, job, nil)
	assert.NoError(t, err)

	jobSession := &Session{
		SeriesID: series.ID,
		JobID:    spanner.NullString{StringVal: job.ID, Valid: true},
	}
	err = sessionRepo.Insert(ctx, jobSession)
	assert.NoError(t, err)

	err = sessionRepo.Start(ctx, jobSession.ID)
	assert.NoError(t, err)

	dbSeries, err = seriesRepo.GetByID(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, session1.ID, dbSeries.LatestSessionID.StringVal)
}
