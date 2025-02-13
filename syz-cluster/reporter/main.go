// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
)

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}

	generator := newReportGenerator(env)
	go generator.Loop(ctx)

	api := NewReporterAPI(service.NewReportService(env))
	log.Printf("listening on port 8080")
	app.Fatalf("listen failed: %v", http.ListenAndServe(":8080", api.Mux()))
}

type reportGenerator struct {
	sessionRepo *db.SessionRepository
	reportRepo  *db.ReportRepository
}

func newReportGenerator(env *app.AppEnvironment) *reportGenerator {
	return &reportGenerator{
		sessionRepo: db.NewSessionRepository(env.Spanner),
		reportRepo:  db.NewReportRepository(env.Spanner),
	}
}

func (rg *reportGenerator) Loop(ctx context.Context) {
	const (
		// There are no deep ideas behind these numbers.
		sleepTime = time.Minute
		limit     = 5
	)
	for {
		err := rg.process(ctx, limit)
		if err != nil {
			app.Errorf("failed to process reports: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepTime):
		}
	}
}

func (rg *reportGenerator) process(ctx context.Context, limit int) error {
	// Consider only recently finished sessions.
	// It helps optimize DB queries + older sessions are not relevant anyway.
	const relevantPeriod = time.Hour * 24 * 3
	list, err := rg.sessionRepo.MissingReportList(ctx,
		time.Now().Add(-relevantPeriod), limit)
	if err != nil {
		return fmt.Errorf("failed to query sessions: %w", err)
	}
	for _, session := range list {
		report := &db.SessionReport{
			SessionID:  session.ID,
			Moderation: true,
		}
		err := rg.reportRepo.Insert(ctx, report)
		if err != nil {
			return fmt.Errorf("failed to insert the report: %w", err)
		}
	}
	return nil
}
