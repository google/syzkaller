// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"context"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

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
