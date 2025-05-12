// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reporter

import (
	"context"
	"fmt"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

const (
	// The frequency of checking for new results to report.
	generateReportsPeriod = time.Minute
	// How many result to check at each loop iteration.
	generateReportsLimit = 5
	// Consider only recently finished sessions.
	// It helps optimize DB queries + older sessions are not relevant anyway.
	relevantReportAge = time.Hour * 24 * 3
)

type ReportGenerator struct {
	sessionRepo *db.SessionRepository
	reportRepo  *db.ReportRepository
}

func NewGenerator(env *app.AppEnvironment) *ReportGenerator {
	return &ReportGenerator{
		sessionRepo: db.NewSessionRepository(env.Spanner),
		reportRepo:  db.NewReportRepository(env.Spanner),
	}
}

func (rg *ReportGenerator) Loop(ctx context.Context) {
	for {
		err := rg.Process(ctx, generateReportsLimit)
		if err != nil {
			app.Errorf("failed to process reports: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(generateReportsPeriod):
		}
	}
}

func (rg *ReportGenerator) Process(ctx context.Context, limit int) error {
	list, err := rg.sessionRepo.MissingReportList(ctx,
		time.Now().Add(-relevantReportAge), limit)
	if err != nil {
		return fmt.Errorf("failed to query sessions: %w", err)
	}
	for _, session := range list {
		report := &db.SessionReport{
			SessionID:  session.ID,
			Moderation: true,
			Reporter:   api.LKMLReporter,
		}
		err := rg.reportRepo.Insert(ctx, report)
		if err != nil {
			return fmt.Errorf("failed to insert the report: %w", err)
		}
	}
	return nil
}
