// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSeriesInsertSession(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionsRepository(client)
	seriesRepo := NewSeriesRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	// This series is indeed without a session.
	list, err := seriesRepo.ListWithoutSession(ctx, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	// Add a new session.
	session := &Session{CreatedAt: time.Now()}
	err = sessionRepo.InsertSession(ctx, series, session)
	assert.NoError(t, err)

	// All sessions are with sessions now.
	list, err = seriesRepo.ListWithoutSession(ctx, 10)
	assert.NoError(t, err)
	assert.Len(t, list, 0)

	// We can also query the information together.

	list2, err := seriesRepo.ListLatest(ctx, time.Time{}, 0)
	assert.NoError(t, err)
	assert.Len(t, list2, 1)
	assert.NotNil(t, list2[0].Session)
}
