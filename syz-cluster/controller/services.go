// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type SeriesService struct {
	sessionRepo *db.SessionRepository
	seriesRepo  *db.SeriesRepository
	blobStorage blob.Storage
}

func NewSeriesService(env *app.AppEnvironment) *SeriesService {
	return &SeriesService{
		sessionRepo: db.NewSessionRepository(env.Spanner),
		seriesRepo:  db.NewSeriesRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

var ErrSessionNotFound = errors.New("session not found")

func (s *SeriesService) GetSessionSeries(ctx context.Context, sessionID string) (*api.Series, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the session: %w", err)
	} else if session == nil {
		return nil, fmt.Errorf("%w: %q", ErrSessionNotFound, sessionID)
	}
	return s.GetSeries(ctx, session.SeriesID)
}

func (s *SeriesService) SkipSession(ctx context.Context, sessionID string, skip *api.SkipRequest) error {
	err := s.sessionRepo.Update(ctx, sessionID, func(session *db.Session) error {
		session.SetSkipReason(skip.Reason)
		return nil
	})
	if errors.Is(err, db.ErrEntityNotFound) {
		return ErrSessionNotFound
	}
	return err
}

var ErrSeriesNotFound = errors.New("series not found")

func (s *SeriesService) GetSeries(ctx context.Context, seriesID string) (*api.Series, error) {
	series, err := s.seriesRepo.GetByID(ctx, seriesID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the series: %w", err)
	} else if series == nil {
		return nil, ErrSeriesNotFound
	}
	patches, err := s.seriesRepo.ListPatches(ctx, series)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch patches: %w", err)
	}
	ret := &api.Series{
		ID:          series.ID,
		Cc:          series.Cc,
		PublishedAt: series.PublishedAt,
	}
	for _, patch := range patches {
		reader, err := s.blobStorage.Read(patch.BodyURI)
		var body []byte
		if err == nil {
			body, err = io.ReadAll(reader)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read patch %q: %w", patch.ID, err)
		}
		ret.Patches = append(ret.Patches, body)
	}
	return ret, nil
}

type BuildService struct {
	buildRepo *db.BuildRepository
}

func NewBuildService(env *app.AppEnvironment) *BuildService {
	return &BuildService{
		buildRepo: db.NewBuildRepository(env.Spanner),
	}
}

func (s *BuildService) Upload(ctx context.Context, req *api.UploadBuildReq) (*api.UploadBuildResp, error) {
	build := &db.Build{
		Arch:       req.Arch,
		ConfigName: req.ConfigName,
		TreeName:   req.TreeName,
		CommitHash: req.CommitHash,
		CommitDate: req.CommitDate,
	}
	if req.SeriesID != "" {
		build.SetSeriesID(req.SeriesID)
	}
	if req.BuildSuccess {
		build.Status = db.BuildSuccess
	} else {
		build.Status = db.BuildFailed
	}
	// TODO: upload config and log.
	err := s.buildRepo.Insert(ctx, build)
	if err != nil {
		return nil, err
	}
	return &api.UploadBuildResp{
		ID: build.ID,
	}, nil
}

func (s *BuildService) LastBuild(ctx context.Context, req *api.LastBuildReq) (*api.Build, error) {
	build, err := s.buildRepo.LastBuiltTree(ctx, req.Arch, req.TreeName, req.ConfigName)
	if build == nil || err != nil {
		return nil, err
	}
	resp := &api.Build{
		Arch:         build.Arch,
		TreeName:     build.TreeName,
		ConfigName:   build.ConfigName,
		CommitHash:   build.CommitHash,
		CommitDate:   build.CommitDate,
		BuildSuccess: true,
	}
	if !build.SeriesID.IsNull() {
		resp.SeriesID = build.SeriesID.String()
	}
	return resp, nil
}

type SessionTestService struct {
	testRepo *db.SessionTestRepository
}

func NewSessionTestService(env *app.AppEnvironment) *SessionTestService {
	return &SessionTestService{
		testRepo: db.NewSessionTestRepository(env.Spanner),
	}
}

func (s *SessionTestService) Save(ctx context.Context, req *api.TestResult) error {
	entity := &db.SessionTest{
		SessionID: req.SessionID,
		TestName:  req.TestName,
		Result:    req.Result,
	}
	if req.BaseBuildID != "" {
		entity.BaseBuildID = spanner.NullString{StringVal: req.BaseBuildID, Valid: true}
	}
	if req.PatchedBuildID != "" {
		entity.PatchedBuildID = spanner.NullString{StringVal: req.PatchedBuildID, Valid: true}
	}
	return s.testRepo.InsertOrUpdate(context.Background(), entity)
}

type FindingService struct {
	findingRepo *db.FindingRepository
	blobStorage blob.Storage
}

func NewFindingService(env *app.AppEnvironment) *FindingService {
	return &FindingService{
		findingRepo: db.NewFindingRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

func (s *FindingService) Save(ctx context.Context, req *api.Finding) error {
	var reportURI, logURI string
	var err error
	if len(req.Log) > 0 {
		logURI, err = s.blobStorage.Store(bytes.NewReader(req.Log))
		if err != nil {
			return fmt.Errorf("failed to save the log: %w", err)
		}
	}
	if len(req.Report) > 0 {
		reportURI, err = s.blobStorage.Store(bytes.NewReader(req.Report))
		if err != nil {
			return fmt.Errorf("failed to save the report: %w", err)
		}
	}
	// TODO: if it's not actually addded, the blob records will be orphaned.
	err = s.findingRepo.Save(ctx, &db.Finding{
		SessionID: req.SessionID,
		TestName:  req.TestName,
		Title:     req.Title,
		ReportURI: reportURI,
		LogURI:    logURI,
	})
	if err == db.ErrFindingExists {
		// It's ok, just ignore.
		return nil
	}
	return err
}
