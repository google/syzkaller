// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/uuid"
)

var ErrPatchTooLarge = errors.New("patch is too large")

type JobService struct {
	jobRepo         *db.JobRepository
	sessionRepo     *db.SessionRepository
	reportRepo      *db.ReportRepository
	findingRepo     *db.FindingRepository
	sessionTestRepo *db.SessionTestRepository
	blobStorage     blob.Storage
}

func NewJobService(env *app.AppEnvironment) *JobService {
	return &JobService{
		jobRepo:         db.NewJobRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		reportRepo:      db.NewReportRepository(env.Spanner),
		findingRepo:     db.NewFindingRepository(env.Spanner),
		sessionTestRepo: db.NewSessionTestRepository(env.Spanner),
		blobStorage:     env.BlobStorage,
	}
}

func (s *JobService) GetJob(ctx context.Context, jobID string) (*api.Job, error) {
	job, err := s.jobRepo.GetByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job %s: %w", jobID, err)
	} else if job == nil {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	var patch []byte
	if job.PatchURI != "" {
		patch, err = blob.ReadAllBytes(s.blobStorage, job.PatchURI)
		if err != nil {
			return nil, fmt.Errorf("failed to read patch: %w", err)
		}
	}

	apiJob := &api.Job{
		ID:       jobID,
		Patch:    patch,
		ReportID: job.ReportID,
	}

	report, err := s.reportRepo.GetByID(ctx, job.ReportID)
	if err != nil && !errors.Is(err, db.ErrEntityNotFound) {
		return nil, fmt.Errorf("failed to fetch report %s: %w", job.ReportID, err)
	}
	if report != nil {
		findings, err := s.findingRepo.ListForSession(ctx, report.SessionID, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to list findings for session %s: %w", report.SessionID, err)
		}
		apiJob.FindingGroups, err = s.getFindingGroups(ctx, report.SessionID, findings)
		if err != nil {
			return nil, err
		}
	}
	return apiJob, nil
}

func (s *JobService) getFindingGroups(ctx context.Context,
	sessionID string, findings []*db.Finding) ([]api.FindingGroup, error) {
	tests, err := s.sessionTestRepo.BySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query session tests: %w", err)
	}
	buildPerTest := map[string]*api.Build{}
	for _, test := range tests {
		if test.PatchedBuild != nil {
			buildPerTest[test.TestName] = &api.Build{
				Arch:       test.PatchedBuild.Arch,
				ConfigName: test.PatchedBuild.ConfigName,
				TreeName:   test.PatchedBuild.TreeName,
				TreeURL:    test.PatchedBuild.TreeURL,
				CommitHash: test.PatchedBuild.CommitHash,
			}
		}
	}
	groups := make(map[string]*api.FindingGroup)
	var keys []string
	for _, f := range findings {
		build := buildPerTest[f.TestName]
		if build == nil {
			continue
		}
		key := fmt.Sprintf("%v|%v|%v|%v", build.TreeName, build.ConfigName,
			build.CommitHash, build.Arch)
		if task, ok := groups[key]; ok {
			task.FindingIDs = append(task.FindingIDs, f.ID)
		} else {
			task = &api.FindingGroup{
				Build:      *build,
				FindingIDs: []string{f.ID},
			}
			groups[key] = task
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	var ret []api.FindingGroup
	for _, key := range keys {
		ret = append(ret, *groups[key])
	}
	return ret, nil
}

func (s *JobService) SubmitJob(ctx context.Context, req *api.SubmitJobRequest) (*api.SubmitJobResponse, error) {
	report, err := s.reportRepo.GetByID(ctx, req.ReportID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session report %s: %w", req.ReportID, err)
	} else if report == nil {
		return nil, fmt.Errorf("session report %s not found", req.ReportID)
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

func JobLink(job *db.Job) string {
	if job == nil {
		return ""
	}
	if job.Reporter == api.LKMLReporter {
		return lore.LinkToMessage(job.ExtID)
	}
	return ""
}
