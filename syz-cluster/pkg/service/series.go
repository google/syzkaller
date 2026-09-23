// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// SeriesService is tested in controller/.

// ParallelBlobOps limits the concurrency of GCS/blob storage operations when reading
// or writing series patches. Sequential uploads of large patch series can time out
// (e.g. within the Spanner transaction or HTTP request), causing series uploads to fail.
// Using 32 concurrent goroutines speeds up GCS operations enough to avoid timeouts
// while keeping resource usage bounded.
const ParallelBlobOps = 32

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
	// Fast path: don't upload patch bodies for a series we already have.
	// This is best effort, seriesRepo.Insert() re-checks it atomically.
	if existing, err := s.seriesRepo.GetByExtID(ctx, series.ExtID); err != nil {
		return nil, fmt.Errorf("failed to check for an existing series: %w", err)
	} else if existing != nil {
		return &api.UploadSeriesResp{Saved: false}, nil
	}
	seriesObj := &db.Series{
		ID:                uuid.NewString(),
		ExtID:             series.ExtID,
		AuthorEmail:       series.AuthorEmail,
		Title:             series.Title,
		Version:           int64(series.Version),
		Link:              series.Link,
		PublishedAt:       series.PublishedAt,
		Cc:                series.Cc,
		BaseCommitHint:    spanner.NullString{StringVal: series.BaseCommitHint, Valid: series.BaseCommitHint != ""},
		XStable:           spanner.NullString{StringVal: series.XStable, Valid: series.XStable != ""},
		XKernelTestBranch: spanner.NullString{StringVal: series.XKernelTestBranch, Valid: series.XKernelTestBranch != ""},
	}
	for _, tag := range series.SubjectTags {
		const tageSizeLimit = 511
		if len(tag) > tageSizeLimit {
			tag = tag[:tageSizeLimit]
		}
		seriesObj.SubjectTags = append(seriesObj.SubjectTags, tag)
	}
	// If we fail below the already written blobs are left orphaned. Let's ignore it for simplicity, patches are not super
	// big.
	var eg errgroup.Group
	eg.SetLimit(ParallelBlobOps)
	patches := make([]*db.Patch, len(series.Patches))
	for i, patch := range series.Patches {
		eg.Go(func() error {
			uri, err := s.blobStorage.Write(bytes.NewReader(patch.Body),
				"Series", hash.String(series.ExtID), "Patches", fmt.Sprint(patch.Seq))
			if err != nil {
				return fmt.Errorf("failed to upload patch body: %w", err)
			}
			patches[i] = &db.Patch{
				Seq:     int64(patch.Seq),
				Title:   patch.Title,
				Link:    patch.Link,
				BodyURI: uri,
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	err := s.seriesRepo.Insert(ctx, seriesObj, patches)
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
		ID:                series.ID,
		ExtID:             series.ExtID,
		Title:             series.Title,
		AuthorEmail:       series.AuthorEmail,
		Version:           int(series.Version),
		Cc:                series.Cc,
		PublishedAt:       series.PublishedAt,
		Link:              series.Link,
		SubjectTags:       series.SubjectTags,
		BaseCommitHint:    series.BaseCommitHint.StringVal,
		XStable:           series.XStable.StringVal,
		XKernelTestBranch: series.XKernelTestBranch.StringVal,
	}
	var eg errgroup.Group
	eg.SetLimit(ParallelBlobOps)
	ret.Patches = make([]api.SeriesPatch, len(patches))
	for i, patch := range patches {
		eg.Go(func() error {
			var body []byte
			if includeBody {
				var err error
				body, err = blob.ReadAllBytes(s.blobStorage, patch.BodyURI)
				if err != nil {
					return fmt.Errorf("failed to read patch %q: %w", patch.ID, err)
				}
			}
			ret.Patches[i] = api.SeriesPatch{
				Seq:   int(patch.Seq),
				Title: patch.Title,
				Link:  patch.Link,
				Body:  body,
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return ret, nil
}
