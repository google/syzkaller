// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
)

type SeriesStatsRepository struct {
	client *spanner.Client
	*genericEntityOps[SeriesStats, string]
}

func NewSeriesStatsRepository(client *spanner.Client) *SeriesStatsRepository {
	return &SeriesStatsRepository{
		client: client,
		genericEntityOps: &genericEntityOps[SeriesStats, string]{
			client:   client,
			keyField: "ID",
			table:    "SeriesStats",
		},
	}
}

type ListOutdatedFilter struct {
	Limit          int
	CurrentVersion string
}

func (repo *SeriesStatsRepository) ListOutdated(ctx context.Context, filter ListOutdatedFilter) ([]*Series, error) {
	ro := repo.client.ReadOnlyTransaction()
	defer ro.Close()

	stmt := spanner.Statement{
		SQL: `SELECT Series.*
			FROM Series
			INNER JOIN Sessions ON Sessions.ID = Series.LatestSessionID
			LEFT JOIN SeriesStats ON SeriesStats.ID = Series.ID
			WHERE (SeriesStats.ID IS NULL OR SeriesStats.StatsVersion != @currentVersion)
			  AND Sessions.FinishedAt IS NOT NULL
			ORDER BY Series.PublishedAt DESC
			LIMIT @limit`,
		Params: map[string]any{
			"currentVersion": filter.CurrentVersion,
			"limit":          int64(filter.Limit),
		},
	}
	return readEntities[Series](ctx, ro, stmt)
}

func (repo *SeriesStatsRepository) BulkUpdate(ctx context.Context, ids []string, cb func(*SeriesStats)) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := repo.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		existing, err := readEntities[SeriesStats](ctx, txn, spanner.Statement{
			SQL:    "SELECT * FROM SeriesStats WHERE ID IN UNNEST(@ids)",
			Params: map[string]any{"ids": ids},
		})
		if err != nil {
			return err
		}

		existingMap := make(map[string]*SeriesStats)
		for _, stat := range existing {
			existingMap[stat.ID] = stat
		}

		var muts []*spanner.Mutation
		for _, id := range ids {
			stat, ok := existingMap[id]
			if !ok {
				return fmt.Errorf("stats for series %q not found", id)
			}
			cb(stat)
			stat.UpdatedAt = time.Now()

			m, err := spanner.UpdateStruct("SeriesStats", stat)
			if err != nil {
				return err
			}
			muts = append(muts, m)
		}

		if len(muts) > 0 {
			return txn.BufferWrite(muts)
		}
		return nil
	})
	return err
}
