// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"fmt"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/uuid"
)

type BuildService struct {
	buildRepo   *db.BuildRepository
	blobStorage blob.Storage
}

func NewBuildService(env *app.AppEnvironment) *BuildService {
	return &BuildService{
		buildRepo:   db.NewBuildRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

func (s *BuildService) Upload(ctx context.Context, req *api.UploadBuildReq) (*api.UploadBuildResp, error) {
	build := &db.Build{
		ID:         uuid.NewString(),
		Arch:       req.Arch,
		ConfigName: req.ConfigName,
		TreeName:   req.TreeName,
		TreeURL:    req.TreeURL,
		CommitHash: req.CommitHash,
		CommitDate: req.CommitDate,
		Compiler:   req.Compiler,
	}
	if req.SeriesID != "" {
		build.SetSeriesID(req.SeriesID)
	}
	if req.BuildSuccess {
		build.Status = db.BuildSuccess
	} else {
		build.Status = db.BuildFailed
	}
	if len(req.Log) > 0 {
		var err error
		build.LogURI, err = s.blobStorage.Write(bytes.NewReader(req.Log), "Build", build.ID, "log")
		if err != nil {
			return nil, fmt.Errorf("failed to write log: %w", err)
		}
	}
	if len(req.Config) > 0 {
		var err error
		build.ConfigURI, err = s.blobStorage.Write(bytes.NewReader(req.Config), "Build", build.ID, "config")
		if err != nil {
			return nil, fmt.Errorf("failed to write kernel config: %w", err)
		}
	}
	err := s.buildRepo.Insert(ctx, build)
	if err != nil {
		return nil, err
	}
	return &api.UploadBuildResp{
		ID: build.ID,
	}, nil
}

func (s *BuildService) LastBuild(ctx context.Context, req *api.LastBuildReq) (*api.Build, error) {
	build, err := s.buildRepo.LastBuiltTree(ctx, &db.LastBuildParams{
		Arch:       req.Arch,
		TreeName:   req.TreeName,
		ConfigName: req.ConfigName,
		Commit:     req.Commit,
		Status:     req.Status,
	})
	if build == nil || err != nil {
		return nil, err
	}
	resp := &api.Build{
		Arch:         build.Arch,
		TreeName:     build.TreeName,
		TreeURL:      build.TreeURL,
		ConfigName:   build.ConfigName,
		CommitHash:   build.CommitHash,
		CommitDate:   build.CommitDate,
		BuildSuccess: build.Status == db.BuildSuccess,
	}
	if !build.SeriesID.IsNull() {
		resp.SeriesID = build.SeriesID.String()
	}
	return resp, nil
}

func makeBuildInfo(url *api.URLGenerator, build *db.Build) api.BuildInfo {
	return api.BuildInfo{
		TreeName:   build.TreeName,
		TreeURL:    build.TreeURL,
		BaseCommit: build.CommitHash,
		Arch:       build.Arch,
		Compiler:   build.Compiler,
		ConfigLink: url.BuildConfig(build.ID),
	}
}
