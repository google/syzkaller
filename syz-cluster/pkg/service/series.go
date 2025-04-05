// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

// SeriesService is tested in controller/.

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

func (s *SeriesService) GetSessionSeries(ctx context.Context, sessionID string) (*api.Series, error) {
	return s.getSessionSeries(ctx, sessionID, true)
}

func (s *SeriesService) GetSessionSeriesShort(ctx context.Context,
	sessionID string) (*api.Series, error) {
	return s.getSessionSeries(ctx, sessionID, false)
}

func (s *SeriesService) getSessionSeries(ctx context.Context, sessionID string,
	includePatches bool) (*api.Series, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the session: %w", err)
	} else if session == nil {
		return nil, fmt.Errorf("%w: %q", ErrSessionNotFound, sessionID)
	}
	return s.getSeries(ctx, session.SeriesID, includePatches)
}

func (s *SeriesService) UploadSeries(ctx context.Context, series *api.Series) (*api.UploadSeriesResp, error) {
	seriesObj := &db.Series{
		ExtID:       series.ExtID,
		AuthorEmail: series.AuthorEmail,
		Title:       series.Title,
		Version:     int64(series.Version),
		Link:        series.Link,
		PublishedAt: series.PublishedAt,
		Cc:          series.Cc,
	}
	err := s.seriesRepo.Insert(ctx, seriesObj, func() ([]*db.Patch, error) {
		var ret []*db.Patch
		for _, patch := range series.Patches {
			// In case of errors, we will waste some space, but let's ignore it for simplicity.
			// Patches are not super big.
			uri, err := s.blobStorage.Store(bytes.NewReader(patch.Body))
			if err != nil {
				return nil, fmt.Errorf("failed to upload patch body: %w", err)
			}
			ret = append(ret, &db.Patch{
				Seq:     int64(patch.Seq),
				Title:   patch.Title,
				Link:    patch.Link,
				BodyURI: uri,
			})
		}
		return ret, nil
	})
	if err != nil {
		if errors.Is(err, db.ErrSeriesExists) {
			return &api.UploadSeriesResp{Saved: false}, nil
		}
		return nil, err
	}
	return &api.UploadSeriesResp{
		ID:    seriesObj.ID,
		Saved: true,
	}, nil
}

var ErrSeriesNotFound = errors.New("series not found")

func (s *SeriesService) GetSeries(ctx context.Context, seriesID string) (*api.Series, error) {
	return s.getSeries(ctx, seriesID, true)
}

func (s *SeriesService) getSeries(ctx context.Context,
	seriesID string, includeBody bool) (*api.Series, error) {
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
		ExtID:       series.ExtID,
		Title:       series.Title,
		AuthorEmail: series.AuthorEmail,
		Version:     int(series.Version),
		Cc:          series.Cc,
		PublishedAt: series.PublishedAt,
	}
	for _, patch := range patches {
		var body []byte
		if includeBody {
			body, err = blob.ReadAllBytes(s.blobStorage, patch.BodyURI)
			if err != nil {
				return nil, fmt.Errorf("failed to read patch %q: %w", patch.ID, err)
			}
		}
		ret.Patches = append(ret.Patches, api.SeriesPatch{
			Seq:   int(patch.Seq),
			Title: patch.Title,
			Link:  patch.Link,
			Body:  body,
		})
	}
	return ret, nil
}
