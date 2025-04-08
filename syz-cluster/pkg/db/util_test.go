// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

type dummyTestData struct {
	t      *testing.T
	ctx    context.Context
	client *spanner.Client
}

func (d *dummyTestData) addSessionTest(session *Session, names ...string) {
	testsRepo := NewSessionTestRepository(d.client)
	for _, name := range names {
		err := testsRepo.InsertOrUpdate(d.ctx, &SessionTest{
			SessionID: session.ID,
			TestName:  name,
			Result:    api.TestPassed,
		})
		assert.NoError(d.t, err)
	}
}

func (d *dummyTestData) dummySession(series *Series) *Session {
	sessionRepo := NewSessionRepository(d.client)
	session := &Session{
		SeriesID:  series.ID,
		CreatedAt: time.Now(),
	}
	err := sessionRepo.Insert(d.ctx, session)
	assert.NoError(d.t, err)
	return session
}

func (d *dummyTestData) startSession(session *Session) {
	sessionRepo := NewSessionRepository(d.client)
	err := sessionRepo.Start(d.ctx, session.ID)
	assert.NoError(d.t, err)
}

func (d *dummyTestData) finishSession(session *Session) {
	sessionRepo := NewSessionRepository(d.client)
	err := sessionRepo.Update(d.ctx, session.ID, func(session *Session) error {
		session.SetFinishedAt(time.Now())
		return nil
	})
	assert.NoError(d.t, err)
}

func (d *dummyTestData) addFinding(session *Session, title, test string) {
	findingRepo := NewFindingRepository(d.client)
	assert.NoError(d.t, findingRepo.Save(d.ctx, &Finding{
		SessionID: session.ID,
		Title:     title,
		TestName:  test,
	}))
}
