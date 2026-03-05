// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/uuid"
)

var ErrPatchTooLarge = errors.New("patch is too large")

type JobService struct {
	jobRepo     *db.JobRepository
	sessionRepo *db.SessionRepository
	reportRepo  *db.ReportRepository
	blobStorage blob.Storage
}

func NewJobService(env *app.AppEnvironment) *JobService {
	return &JobService{
		jobRepo:     db.NewJobRepository(env.Spanner),
		sessionRepo: db.NewSessionRepository(env.Spanner),
		reportRepo:  db.NewReportRepository(env.Spanner),
		blobStorage: env.BlobStorage,
	}
}

func (s *JobService) SubmitJob(ctx context.Context, req *api.SubmitJobRequest) (*api.SubmitJobResponse, error) {
	report, err := s.reportRepo.GetByID(ctx, req.ReportID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session report %s: %w", req.ReportID, err)
	}
	origSession, err := s.sessionRepo.GetByID(ctx, report.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session %s: %w", report.SessionID, err)
	}

	job := &db.Job{
		ID:        uuid.NewString(),
		Type:      string(req.Type),
		CreatedAt: time.Now(),
		ReportID:  req.ReportID,
		Reporter:  req.Reporter,
		User:      req.User,
		ExtID:     req.ExtID,
		Cc:        req.Cc,
	}
	if job.ExtID == "" {
		job.ExtID = uuid.NewString()
	}

	const maxPatchSize = 1000 * 1000 // 1 MB.
	if len(req.PatchData) > maxPatchSize {
		return nil, fmt.Errorf("%w: %v > %v bytes", ErrPatchTooLarge, len(req.PatchData), maxPatchSize)
	}

	err = s.jobRepo.Insert(ctx, job, func(job *db.Job) error {
		if len(req.PatchData) == 0 {
			return nil
		}
		uri, err := s.blobStorage.Write(bytes.NewReader(req.PatchData), "Job", job.ID, "patch")
		if err != nil {
			return fmt.Errorf("failed to save patch to blob storage: %w", err)
		}
		job.PatchURI = uri
		return nil
	})

	if err != nil {
		if errors.Is(err, db.ErrJobExists) {
			return nil, db.ErrJobExists
		}
		return nil, fmt.Errorf("failed to insert job: %w", err)
	}

	session := &db.Session{
		SeriesID:  origSession.SeriesID,
		CreatedAt: time.Now(),
	}
	session.SetJobID(job.ID)

	err = s.sessionRepo.Insert(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to insert session: %w", err)
	}

	return &api.SubmitJobResponse{JobID: job.ID, SessionID: session.ID}, nil
}
