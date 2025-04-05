// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestFindingRepo(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)
	findingRepo := NewFindingRepository(client)
	testsRepo := NewSessionTestRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	session := &Session{SeriesID: series.ID}
	err = sessionRepo.Insert(ctx, session)
	assert.NoError(t, err)

	// Add test steps.
	for _, name := range []string{"first", "second"} {
		err = testsRepo.InsertOrUpdate(ctx, &SessionTest{
			SessionID: session.ID,
			TestName:  name,
			Result:    api.TestPassed,
		})
		assert.NoError(t, err)
	}

	// Add findings.
	toInsert := []*Finding{
		{
			TestName:  "first",
			Title:     "A",
			SessionID: session.ID,
		},
		{
			TestName:  "first",
			Title:     "B",
			SessionID: session.ID,
		},
		{
			TestName:  "second",
			Title:     "A",
			SessionID: session.ID,
		},
	}
	// Insert them all.
	for _, finding := range toInsert {
		err := findingRepo.Save(ctx, finding)
		assert.NoError(t, err, "finding=%q", finding)
	}
	// Now it should report a duplicate each time.
	for _, finding := range toInsert {
		err := findingRepo.Save(ctx, finding)
		assert.ErrorIs(t, err, ErrFindingExists)
	}

	list, err := findingRepo.ListForSession(ctx, session.ID)
	assert.NoError(t, err)
	assert.Equal(t, toInsert, list)
}
