// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type BaseFindingService struct {
	baseFindingRepo *db.BaseFindingRepository
	buildRepo       *db.BuildRepository
}

func NewBaseFindingService(env *app.AppEnvironment) *BaseFindingService {
	return &BaseFindingService{
		baseFindingRepo: db.NewBaseFindingRepository(env.Spanner),
		buildRepo:       db.NewBuildRepository(env.Spanner),
	}
}

var ErrBuildNotFound = errors.New("build not found")

func (s *BaseFindingService) Upload(ctx context.Context, info *api.BaseFindingInfo) error {
	finding, err := s.makeBaseFinding(ctx, info)
	if err != nil {
		return err
	}
	return s.baseFindingRepo.Save(ctx, finding)
}

func (s *BaseFindingService) Status(ctx context.Context, info *api.BaseFindingInfo) (
	*api.BaseFindingStatus, error) {
	finding, err := s.makeBaseFinding(ctx, info)
	if err != nil {
		return nil, err
	}
	exists, err := s.baseFindingRepo.Exists(ctx, finding)
	if err != nil {
		return nil, err
	}
	return &api.BaseFindingStatus{
		Observed: exists,
	}, nil
}

func (s *BaseFindingService) makeBaseFinding(ctx context.Context, info *api.BaseFindingInfo) (*db.BaseFinding, error) {
	build, err := s.buildRepo.GetByID(ctx, info.BuildID)
	if err != nil {
		return nil, fmt.Errorf("failed to query build: %w", err)
	} else if build == nil {
		return nil, ErrBuildNotFound
	}
	return &db.BaseFinding{
		CommitHash: build.CommitHash,
		Config:     build.ConfigName,
		Arch:       build.Arch,
		Title:      info.Title,
	}, nil
}
