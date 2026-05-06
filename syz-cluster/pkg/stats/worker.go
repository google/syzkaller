// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"context"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

const currentStatsVersion = "v1"

type Worker struct {
	seriesRepo      *db.SeriesRepository
	seriesStatsRepo *db.SeriesStatsRepository
	statsRepo       *db.StatsRepository
	interval        time.Duration
}

func NewWorker(
	seriesRepo *db.SeriesRepository,
	seriesStatsRepo *db.SeriesStatsRepository,
	statsRepo *db.StatsRepository,
	interval time.Duration,
) *Worker {
	return &Worker{
		seriesRepo:      seriesRepo,
		seriesStatsRepo: seriesStatsRepo,
		statsRepo:       statsRepo,
		interval:        interval,
	}
}

func (w *Worker) Loop(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.RunOnce(ctx)
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) {
	const batchSize = 10
	seriesList, err := w.seriesStatsRepo.ListOutdated(ctx, db.ListOutdatedFilter{
		Limit:          batchSize,
		CurrentVersion: currentStatsVersion,
	})
	if err != nil {
		log.Errorf("failed to list outdated series for stats: %v", err)
		return
	}

	for _, series := range seriesList {
		err := w.processSeries(ctx, series)
		if err != nil {
			log.Errorf("failed to process stats for series %v: %v", series.ID, err)
		}
	}
}

func (w *Worker) processSeries(ctx context.Context, series *db.Series) error {
	count, err := w.statsRepo.CountPreventedBugs(ctx, series.ID)
	if err != nil {
		return err
	}
	stats := &db.SeriesStats{
		ID:            series.ID,
		StatsVersion:  currentStatsVersion,
		PreventedBugs: count,
		UpdatedAt:     time.Now(),
	}
	if err := w.seriesStatsRepo.Upsert(ctx, stats); err != nil {
		return err
	}
	// For prevented bugs calculation, we care only about the latest version.
	// So we reset the count for all previous ones.
	otherVersions, err := w.seriesRepo.ListPreviousVersions(ctx, series)
	if err != nil {
		return err
	}
	var otherIDs []string
	for _, v := range otherVersions {
		otherIDs = append(otherIDs, v.ID)
	}
	if len(otherIDs) > 0 {
		err = w.seriesStatsRepo.BulkUpdate(ctx, otherIDs, func(s *db.SeriesStats) {
			s.PreventedBugs = 0
		})
		if err != nil {
			return err
		}
	}
	return nil
}
