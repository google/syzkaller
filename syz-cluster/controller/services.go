// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

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
