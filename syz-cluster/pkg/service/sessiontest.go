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
)

type SessionTestService struct {
	testRepo    *db.SessionTestRepository
	blobStorage blob.Storage
}

func NewSessionTestService(env *app.AppEnvironment) *SessionTestService {
	return &SessionTestService{
		testRepo:    db.NewSessionTestRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

func (s *SessionTestService) Save(ctx context.Context, req *api.TestResult) error {
	entity, err := s.testRepo.Get(ctx, req.SessionID, req.TestName)
	if err != nil {
		return fmt.Errorf("failed to query the test: %w", err)
	} else if entity == nil {
		entity = &db.SessionTest{
			SessionID: req.SessionID,
			TestName:  req.TestName,
		}
	}
	entity.Result = req.Result
	entity.UpdatedAt = time.Now()
	if req.BaseBuildID != "" {
		entity.BaseBuildID = spanner.NullString{StringVal: req.BaseBuildID, Valid: true}
	}
	if req.PatchedBuildID != "" {
		entity.PatchedBuildID = spanner.NullString{StringVal: req.PatchedBuildID, Valid: true}
	}
	if entity.LogURI != "" {
		err := s.blobStorage.Update(entity.LogURI, bytes.NewReader(req.Log))
		if err != nil {
			return fmt.Errorf("failed to update the log: %w", err)
		}
	} else if len(req.Log) > 0 {
		// TODO: it will leak if we fail to save the entity.
		uri, err := s.blobStorage.Store(bytes.NewReader(req.Log))
		if err != nil {
			return fmt.Errorf("failed to save the log: %w", err)
		}
		entity.LogURI = uri
	}
	return s.testRepo.InsertOrUpdate(context.Background(), entity)
}
