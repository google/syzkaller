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
	logURI := entity.LogURI
	if len(req.Log) > 0 {
		logURI, err = s.blobStorage.Write(bytes.NewReader(req.Log),
			"Session", req.SessionID, "Test", req.TestName, "log")
		if err != nil {
			return fmt.Errorf("failed to save the log: %w", err)
		}
	}
	return s.testRepo.InsertOrUpdate(ctx, entity, func(test *db.SessionTest) {
		test.Result = req.Result
		test.UpdatedAt = time.Now()
		test.LogURI = logURI
		if req.BaseBuildID != "" {
			test.BaseBuildID = spanner.NullString{StringVal: req.BaseBuildID, Valid: true}
		}
		if req.PatchedBuildID != "" {
			test.PatchedBuildID = spanner.NullString{StringVal: req.PatchedBuildID, Valid: true}
		}
	})
}

func (s *SessionTestService) SaveArtifacts(ctx context.Context, sessionID, testName string, reader io.Reader) error {
	entity, err := s.testRepo.Get(ctx, sessionID, testName)
	if err != nil {
		return fmt.Errorf("failed to query the test: %w", err)
	} else if entity == nil {
		return fmt.Errorf("the test has not been submitted yet")
	}
	archiveURI, err := s.blobStorage.Write(reader, "Session", sessionID, "Test", testName, "artifacts")
	if err != nil {
		return fmt.Errorf("failed to save the artifacts archive: %w", err)
	}
	return s.testRepo.InsertOrUpdate(ctx, entity, func(test *db.SessionTest) {
		test.ArtifactsArchiveURI = archiveURI
	})
}
