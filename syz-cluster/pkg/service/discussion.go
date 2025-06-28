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

// DiscussionService implements the functionality necessary for tracking replies under the bug reports.
// Each report is assumed to have an ID and have an InReplyTo ID that either points to another reply or
// to the original bug report.
// DiscussionService offers the methods to record such replies and, for each reply, to determine the original
// discussed bug report.
type DiscussionService struct {
	reportRepo      *db.ReportRepository
	reportReplyRepo *db.ReportReplyRepository
}

func NewDiscussionService(env *app.AppEnvironment) *DiscussionService {
	return &DiscussionService{
		reportRepo:      db.NewReportRepository(env.Spanner),
		reportReplyRepo: db.NewReportReplyRepository(env.Spanner),
	}
}

func (d *DiscussionService) RecordReply(ctx context.Context, req *api.RecordReplyReq) (*api.RecordReplyResp, error) {
	reportID, err := d.identifyReport(ctx, req)
	if err != nil {
		return nil, err
	} else if reportID == "" {
		// We could not find the related report.
		return &api.RecordReplyResp{}, nil
	}
	err = d.reportReplyRepo.Insert(ctx, &db.ReportReply{
		ReportID:  reportID,
		MessageID: req.MessageID,
		Time:      req.Time,
	})
	if errors.Is(err, db.ErrReportReplyExists) {
		return &api.RecordReplyResp{
			ReportID: reportID,
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to save the reply: %w", err)
	}
	return &api.RecordReplyResp{
		ReportID: reportID,
		New:      true,
	}, nil
}

func (d *DiscussionService) LastReply(ctx context.Context, reporter string) (*api.LastReplyResp, error) {
	reply, err := d.reportReplyRepo.LastForReporter(ctx, reporter)
	if err != nil {
		return nil, fmt.Errorf("failed to query the last report: %w", err)
	}
	if reply != nil {
		return &api.LastReplyResp{Time: reply.Time}, nil
	}
	return &api.LastReplyResp{}, nil
}

func (d *DiscussionService) identifyReport(ctx context.Context, req *api.RecordReplyReq) (string, error) {
	// If the report ID was passed explicitly, just verify it.
	if req.ReportID != "" {
		report, err := d.reportRepo.GetByID(ctx, req.ReportID)
		if err != nil {
			return "", fmt.Errorf("failed to query the report: %w", err)
		} else if report != nil {
			return report.ID, nil
		}
		return "", nil
	}
	// Now try to find a matching reply.
	reportID, err := d.reportReplyRepo.FindParentReportID(ctx, req.Reporter, req.InReplyTo)
	if err != nil {
		return "", fmt.Errorf("search among the replies failed: %w", err)
	}
	return reportID, nil
}
