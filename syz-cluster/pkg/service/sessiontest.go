// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	// TODO: the code does not really handle simultaneous requests.
	if len(req.Log) > 0 {
		entity.LogURI, err = s.uploadOrUpdate(ctx, entity.LogURI, bytes.NewReader(req.Log))
		if err != nil {
			return fmt.Errorf("failed to save the log: %w", err)
		}
	}
	return s.testRepo.InsertOrUpdate(ctx, entity)
}

// TODO: this function has the same problems as Save().
func (s *SessionTestService) SaveArtifacts(ctx context.Context, sessionID, testName string, reader io.Reader) error {
	entity, err := s.testRepo.Get(ctx, sessionID, testName)
	if err != nil {
		return fmt.Errorf("failed to query the test: %w", err)
	} else if entity == nil {
		return fmt.Errorf("the test has not been submitted yet")
	}
	newArchiveURI, err := s.uploadOrUpdate(ctx, entity.ArtifactsArchiveURI, reader)
	if err != nil {
		return fmt.Errorf("failed to save the artifacts archive: %w", err)
	}
	entity.ArtifactsArchiveURI = newArchiveURI
	return s.testRepo.InsertOrUpdate(ctx, entity)
}

func (s *SessionTestService) uploadOrUpdate(ctx context.Context, uri string, reader io.Reader) (string, error) {
	if uri != "" {
		err := s.blobStorage.Update(uri, reader)
		if err != nil {
			return "", fmt.Errorf("failed to update: %w", err)
		}
		return uri, nil
	}
	// TODO: it will leak if we fail to save the entity.
	uri, err := s.blobStorage.Store(reader)
	if err != nil {
		return "", fmt.Errorf("failed to save: %w", err)
	}
	return uri, nil
}
