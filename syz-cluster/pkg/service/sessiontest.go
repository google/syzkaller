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
	var logURI string
	if err := s.testRepo.InsertOrUpdate(ctx, entity, func(test *db.SessionTest) error {
		test.Result = req.Result
		test.UpdatedAt = time.Now()
		if len(req.Log) > 0 {
			var err error
			test.LogURI, err = s.blobStorage.NewURI()
			if err != nil {
				return err
			}
		}
		logURI = test.LogURI
		if req.BaseBuildID != "" {
			test.BaseBuildID = spanner.NullString{StringVal: req.BaseBuildID, Valid: true}
		}
		if req.PatchedBuildID != "" {
			test.PatchedBuildID = spanner.NullString{StringVal: req.PatchedBuildID, Valid: true}
		}
		return nil
	}); err != nil {
		return err
	}
	if logURI != "" {
		err := s.blobStorage.Write(logURI, bytes.NewReader(req.Log))
		if err != nil {
			return fmt.Errorf("failed to save the log: %w", err)
		}
	}
	return nil
}

func (s *SessionTestService) SaveArtifacts(ctx context.Context, sessionID, testName string, reader io.Reader) error {
	entity, err := s.testRepo.Get(ctx, sessionID, testName)
	if err != nil {
		return fmt.Errorf("failed to query the test: %w", err)
	} else if entity == nil {
		return fmt.Errorf("the test has not been submitted yet")
	}
	var archiveURI string
	if err := s.testRepo.InsertOrUpdate(ctx, entity, func(test *db.SessionTest) error {
		if test.ArtifactsArchiveURI == "" {
			var err error
			test.ArtifactsArchiveURI, err = s.blobStorage.NewURI()
			if err != nil {
				return err
			}
		}
		archiveURI = test.ArtifactsArchiveURI
		return nil
	}); err != nil {
		return err
	}
	if err := s.blobStorage.Write(archiveURI, reader); err != nil {
		return fmt.Errorf("failed to upload the archive: %w", err)
	}
	return nil
}
