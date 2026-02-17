// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionTestStepRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSessionTestStepRepository(client)
	data := &dummyTestData{t: t, ctx: ctx, client: client}

	series := data.dummySeries()
	session := data.dummySession(series)
	data.addSessionTest(session, "test1")
	finding1 := data.addFinding(session, "title1", "test1")
	finding2 := data.addFinding(session, "title2", "test1")

	step := &SessionTestStep{
		ID:        uuid.NewString(),
		SessionID: session.ID,
		TestName:  "test1",
		Title:     "title1",
		FindingID: spanner.NullString{StringVal: finding1.ID, Valid: true},
		Target:    api.StepTargetPatched,
		Result:    api.StepResultPassed,
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Store(ctx, SessionTestStepID{
		SessionID: step.SessionID,
		TestName:  step.TestName,
		Title:     step.Title,
	}, func(session *Session, old *SessionTestStep) (*SessionTestStep, error) {
		return step, nil
	}))

	steps, err := repo.ListForSession(ctx, session.ID, "test1")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.NotEmpty(t, steps[0].ID)
	assert.Equal(t, step.TestName, steps[0].TestName)
	assert.Equal(t, step.FindingID, steps[0].FindingID)

	// Add another step.
	step2 := &SessionTestStep{
		ID:        uuid.NewString(),
		SessionID: session.ID,
		TestName:  "test1",
		Title:     "title2",
		FindingID: spanner.NullString{StringVal: finding2.ID, Valid: true},
		Target:    api.StepTargetBase,
		Result:    api.StepResultFailed,
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Store(ctx, SessionTestStepID{
		SessionID: step2.SessionID,
		TestName:  step2.TestName,
		Title:     step2.Title,
	}, func(session *Session, old *SessionTestStep) (*SessionTestStep, error) {
		return step2, nil
	}))

	steps, err = repo.ListForSession(ctx, session.ID, "test1")
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, finding1.ID, steps[0].FindingID.StringVal)
	assert.Equal(t, finding2.ID, steps[1].FindingID.StringVal)
}
