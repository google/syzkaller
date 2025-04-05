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
	reportRepo     *db.ReportRepository
	seriesService  *SeriesService
	findingService *FindingService
}

func NewReportService(env *app.AppEnvironment) *ReportService {
	return &ReportService{
		reportRepo:     db.NewReportRepository(env.Spanner),
		seriesService:  NewSeriesService(env),
		findingService: NewFindingService(env),
	}
}

var ErrReportNotFound = errors.New("report is not found")

func (rs *ReportService) Update(ctx context.Context, id string, req *api.UpdateReportReq) error {
	// TODO: validate the link?
	err := rs.reportRepo.Update(ctx, id, func(rep *db.SessionReport) error {
		if req.Link != "" {
			rep.Link = req.Link
		}
		return nil
	})
	if errors.Is(err, db.ErrEntityNotFound) {
		return ErrReportNotFound
	}
	return err
}

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
		return nil
	} else if !rep.Moderation {
		return ErrNotOnModeration
	}
	// In case of a concurrent Upstream() call or an Upstream() invocation on
	// an already upstreamed report, the "NoDupSessionReports" index should
	// prevent duplications.
	err = rs.reportRepo.Insert(ctx, &db.SessionReport{
		SessionID: rep.SessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to schedule a new report: %w", err)
	}
	return nil
}

func (rs *ReportService) Next(ctx context.Context) (*api.NextReportResp, error) {
	list, err := rs.reportRepo.ListNotReported(ctx, 1)
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
	findings, err := rs.findingService.List(ctx, report.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	return &api.NextReportResp{
		Report: &api.SessionReport{
			ID:         report.ID,
			Moderation: report.Moderation,
			Series:     series,
			Findings:   findings,
		},
	}, nil
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
