// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/uuid"
)

type SessionTestStepService struct {
	repo        *db.SessionTestStepRepository
	blobStorage blob.Storage
}

func NewSessionTestStepService(env *app.AppEnvironment) *SessionTestStepService {
	return &SessionTestStepService{
		repo:        db.NewSessionTestStepRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

func (s *SessionTestStepService) Save(ctx context.Context, sessionID string, step *api.SessionTestStep) error {
	return s.repo.Store(ctx, db.SessionTestStepID{
		SessionID: sessionID,
		TestName:  step.TestName,
		Title:     step.Title,
		Target:    step.Target,
	}, func(session *db.Session, old *db.SessionTestStep) (*db.SessionTestStep, error) {
		newStep := &db.SessionTestStep{
			SessionID: sessionID,
			TestName:  step.TestName,
			Title:     step.Title,
			FindingID: spanner.NullString{StringVal: step.FindingID, Valid: step.FindingID != ""},
			Target:    step.Target,
			Result:    step.Result,
			CreatedAt: time.Now(),
		}
		if old != nil {
			newStep.ID = old.ID
		} else {
			newStep.ID = uuid.NewString()
		}
		if len(step.Log) > 0 {
			uri, err := s.blobStorage.Write(bytes.NewReader(step.Log), "SessionTestStep", newStep.ID, "log")
			if err != nil {
				return nil, fmt.Errorf("failed to save log: %w", err)
			}
			newStep.LogURI = uri
		}
		return newStep, nil
	})
}
