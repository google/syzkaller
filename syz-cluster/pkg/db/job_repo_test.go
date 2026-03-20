// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJobRepo(t *testing.T) {
	ctx := context.Background()
	client, _ := NewTransientDB(t)
	repo := NewJobRepository(client)

	dummy := &dummyTestData{t: t, ctx: ctx, client: client}
	series := dummy.dummySeries()
	session := dummy.dummySession(series)
	report := dummy.dummyReport(session)

	job := &Job{
		ID:        uuid.NewString(),
		Type:      JobPatchTest,
		CreatedAt: time.Now(),
		ReportID:  report.ID,
		Reporter:  "test-reporter",
		User:      "user@email",
		ExtID:     "msg-1234",
		PatchURI:  "gs://bucket/patch.diff",
	}

	err := repo.Insert(ctx, job, nil)
	assert.NoError(t, err)

	// Prevent duplicate insert with the same MessageID.
	jobDup := &Job{
		ID:        uuid.NewString(),
		Type:      JobPatchTest,
		CreatedAt: time.Now(),
		ReportID:  report.ID,
		Reporter:  "test-reporter",
		User:      "user@email",
		ExtID:     "msg-1234",
		PatchURI:  "gs://bucket/patch.diff",
	}
	err = repo.Insert(ctx, jobDup, nil)
	assert.True(t, errors.Is(err, ErrJobExists))
}
