// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type ReportService struct {
	reportRepo      *db.ReportRepository
	sessionRepo     *db.SessionRepository
	jobRepo         *db.JobRepository
	sessionTestRepo *db.SessionTestRepository
	testStepRepo    *db.SessionTestStepRepository
	seriesService   *SeriesService
	findingService  *FindingService
	urls            *api.URLGenerator
}

func NewReportService(env *app.AppEnvironment) *ReportService {
	return &ReportService{
		urls:            env.URLs,
		reportRepo:      db.NewReportRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		jobRepo:         db.NewJobRepository(env.Spanner),
		sessionTestRepo: db.NewSessionTestRepository(env.Spanner),
		testStepRepo:    db.NewSessionTestStepRepository(env.Spanner),
		seriesService:   NewSeriesService(env),
		findingService:  NewFindingService(env),
	}
}

var ErrReportNotFound = errors.New("report is not found")

func (rs *ReportService) Confirm(ctx context.Context, id string) error {
	err := rs.reportRepo.Update(ctx, id, func(rep *db.SessionReport) error {
		if rep.ReportedAt.IsNull() {
			rep.SetReportedAt(time.Now())
		}
		// TODO: fail if already confirmed?
		return nil
	})
	if errors.Is(err, db.ErrEntityNotFound) {
		return ErrReportNotFound
	}
	return err
}

var ErrNotOnModeration = errors.New("the report is not on moderation")

func (rs *ReportService) Upstream(ctx context.Context, id string, req *api.UpstreamReportReq) error {
	rep, err := rs.query(ctx, id)
	if err != nil {
		return err
	} else if !rep.Moderation {
		return ErrNotOnModeration
	}
	// In case of a concurrent Upstream() call or an Upstream() invocation on
	// an already upstreamed report, the "NoDupSessionReports" index should
	// prevent duplications.
	err = rs.reportRepo.Insert(ctx, &db.SessionReport{
		SessionID: rep.SessionID,
		Reporter:  rep.Reporter,
	})
	if err != nil {
		return fmt.Errorf("failed to schedule a new report: %w", err)
	}
	return nil
}

func (rs *ReportService) Invalidate(ctx context.Context, id string) error {
	rep, err := rs.query(ctx, id)
	if err != nil {
		return err
	}
	// For now, invalidate all the findings at once - later we can do it more selectively.
	return rs.findingService.InvalidateSession(ctx, rep.SessionID)
}

const maxFindingsPerReport = 5

func (rs *ReportService) Next(ctx context.Context, reporter string) (*api.NextReportResp, error) {
	list, err := rs.reportRepo.ListNotReported(ctx, reporter, 1)
	if err != nil {
		return nil, err
	} else if len(list) != 1 {
		return &api.NextReportResp{}, nil
	}
	report := list[0]
	series, err := rs.seriesService.GetSessionSeriesShort(ctx, report.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	findings, err := rs.findingService.List(ctx, report.SessionID, maxFindingsPerReport)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	reportObj := &api.SessionReport{
		ID:         report.ID,
		Moderation: report.Moderation,
		Series:     series,
		Link:       rs.urls.Series(series.ID),
		Findings:   findings,
	}

	session, err := rs.sessionRepo.GetByID(ctx, report.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	if session.JobID.Valid {
		reportObj.Type = api.ReportTypePatchTest
		if err := rs.populatePatchTestReport(ctx, reportObj, session); err != nil {
			return nil, err
		}
	} else {
		reportObj.Type = api.ReportTypeBug
		reportObj.InReplyTo = series.ExtID
	}

	return &api.NextReportResp{
		Report: reportObj,
	}, nil
}

func (rs *ReportService) populatePatchTestReport(ctx context.Context, reportObj *api.SessionReport,
	session *db.Session) error {
	job, err := rs.jobRepo.GetByID(ctx, session.JobID.StringVal)
	if err != nil {
		return fmt.Errorf("failed to query job: %w", err)
	}
	reportObj.InReplyTo = job.ExtID
	if reportObj.InReplyTo == "" {
		reportObj.InReplyTo = reportObj.Series.ExtID
	}
	reportObj.PatchLink = rs.urls.JobPatch(job.ID)

	tests, err := rs.sessionTestRepo.BySessionRaw(ctx, session.ID)
	if err != nil {
		return fmt.Errorf("failed to query session tests: %w", err)
	}
	var apiTests []api.ReportTest
	for _, t := range tests {
		rt := api.ReportTest{
			Name:   t.TestName,
			Status: t.Result,
		}
		steps, err := rs.testStepRepo.ListForSession(ctx, session.ID, t.TestName)
		if err != nil {
			return fmt.Errorf("failed to query test steps: %w", err)
		}
		for _, step := range steps {
			name := step.Title
			if step.Target != "" {
				name += fmt.Sprintf(" (%s)", step.Target)
			}
			rt.Steps = append(rt.Steps, api.ReportTestStep{
				Name:   name,
				Status: step.Result,
			})
		}
		apiTests = append(apiTests, rt)
	}

	reportObj.Tests = apiTests
	return nil
}

func (rs *ReportService) query(ctx context.Context, id string) (*db.SessionReport, error) {
	rep, err := rs.reportRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query the report: %w", err)
	} else if rep == nil {
		return nil, ErrReportNotFound
	}
	return rep, err
}
