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

type FindingService struct {
	findingRepo     *db.FindingRepository
	sessionTestRepo *db.SessionTestRepository
	buildRepo       *db.BuildRepository
	urls            *api.URLGenerator
	blobStorage     blob.Storage
}

func NewFindingService(env *app.AppEnvironment) *FindingService {
	return &FindingService{
		findingRepo:     db.NewFindingRepository(env.Spanner),
		blobStorage:     env.BlobStorage,
		urls:            env.URLs,
		buildRepo:       db.NewBuildRepository(env.Spanner),
		sessionTestRepo: db.NewSessionTestRepository(env.Spanner),
	}
}

func (s *FindingService) Save(ctx context.Context, req *api.NewFinding) error {
	finding := &db.Finding{
		ID:        uuid.NewString(),
		SessionID: req.SessionID,
		TestName:  req.TestName,
		Title:     req.Title,
	}
	var err error

	type saveAsset struct {
		saveTo *string
		value  []byte
		name   string
	}

	for _, asset := range []saveAsset{
		{&finding.LogURI, req.Log, "log"},
		{&finding.ReportURI, req.Report, "report"},
		{&finding.SyzReproURI, req.SyzRepro, "syz_repro"},
		{&finding.SyzReproOptsURI, req.SyzReproOpts, "syz_repro_opts"},
		{&finding.CReproURI, req.CRepro, "c_repro"},
	} {
		if len(asset.value) == 0 {
			continue
		}
		*asset.saveTo, err = s.blobStorage.Write(bytes.NewReader(asset.value), "Finding", finding.ID, asset.name)
		if err != nil {
			return fmt.Errorf("failed to save %s: %w", asset.name, err)
		}
	}

	// TODO: if it's not actually addded, the blobs above will be orphaned.
	err = s.findingRepo.Save(ctx, finding)
	if err == db.ErrFindingExists {
		// It's ok, just ignore.
		return nil
	}
	return err
}

func (s *FindingService) List(ctx context.Context, sessionID string, limit int) ([]*api.Finding, error) {
	list, err := s.findingRepo.ListForSession(ctx, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query the list: %w", err)
	}
	tests, err := s.sessionTestRepo.BySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query session tests: %w", err)
	}
	testPerName := map[string]*db.FullSessionTest{}
	for _, test := range tests {
		testPerName[test.TestName] = test
	}
	var ret []*api.Finding
	for _, item := range list {
		finding := &api.Finding{
			Title:  item.Title,
			LogURL: s.urls.FindingLog(item.ID),
		}
		if item.SyzReproURI != "" {
			finding.LinkSyzRepro = s.urls.FindingSyzRepro(item.ID)
		}
		if item.CReproURI != "" {
			finding.LinkCRepro = s.urls.FindingCRepro(item.ID)
		}
		build := testPerName[item.TestName].PatchedBuild
		if build != nil {
			finding.Build = makeBuildInfo(s.urls, build)
		}
		bytes, err := blob.ReadAllBytes(s.blobStorage, item.ReportURI)
		if err != nil {
			return nil, fmt.Errorf("failed to read the report: %w", err)
		}
		finding.Report = string(bytes)
		ret = append(ret, finding)
	}
	return ret, nil
}
