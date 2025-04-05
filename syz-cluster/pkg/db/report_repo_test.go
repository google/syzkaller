// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestReportRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)
	reportRepo := NewReportRepository(client)

	var keys []string
	for i := 0; i < 3; i++ {
		series := &Series{ExtID: fmt.Sprintf("series%d", i)}
		err := seriesRepo.Insert(ctx, series, nil)
		assert.NoError(t, err)

		session := &Session{SeriesID: series.ID}
		err = sessionRepo.Insert(ctx, session)
		assert.NoError(t, err)

		report := &SessionReport{SessionID: session.ID}
		err = reportRepo.Insert(ctx, report)
		assert.NoError(t, err)
		keys = append(keys, report.ID)
	}

	list, err := reportRepo.ListNotReported(ctx, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 3)

	err = reportRepo.Update(ctx, keys[0], func(rep *SessionReport) error {
		rep.SetReportedAt(time.Now())
		return nil
	})
	assert.NoError(t, err)

	// Now one less.
	list, err = reportRepo.ListNotReported(ctx, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestSessionsWithoutReports(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)
	findingRepo := NewFindingRepository(client)
	testsRepo := NewSessionTestRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	// Set up 3 sessions, 2 of which would have a finding.
	var sessions []*Session
	for i := 0; i < 3; i++ {
		session := &Session{SeriesID: series.ID}
		sessions = append(sessions, session)
		err = sessionRepo.Insert(ctx, session)
		assert.NoError(t, err)
		if i == 0 || i == 1 {
			// Fake a test and a finding.
			err = testsRepo.InsertOrUpdate(ctx, &SessionTest{
				SessionID: session.ID,
				TestName:  "test",
				Result:    api.TestPassed,
			})
			assert.NoError(t, err)
			err = findingRepo.Save(ctx, &Finding{
				SessionID: session.ID,
				TestName:  "test",
				Title:     "A",
			})
			assert.NoError(t, err)
		}
	}
	// For now it should be 0 -- none are finished.
	list, err := sessionRepo.MissingReportList(ctx, time.Time{}, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 0)

	// Finish all sessions.
	for _, session := range sessions {
		err := sessionRepo.Update(ctx, session.ID, func(session *Session) error {
			session.SetFinishedAt(time.Now())
			return nil
		})
		assert.NoError(t, err)
	}

	// Now it should be 2.
	list, err = sessionRepo.MissingReportList(ctx, time.Time{}, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 2)

	// Create a report for the first session.
	reportRepo := NewReportRepository(client)
	err = reportRepo.Insert(ctx, &SessionReport{SessionID: sessions[0].ID})
	assert.NoError(t, err)

	// Now only the second session must be returned.
	list, err = sessionRepo.MissingReportList(ctx, time.Time{}, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, list[0].ID, sessions[1].ID)
}
