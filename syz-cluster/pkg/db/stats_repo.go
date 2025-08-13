// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
)

type StatsRepository struct {
	client *spanner.Client
}

func NewStatsRepository(client *spanner.Client) *StatsRepository {
	return &StatsRepository{
		client: client,
	}
}

type CountPerWeek struct {
	Date  time.Time `spanner:"Date"`
	Count int64     `spanner:"Count"`
}

func (repo *StatsRepository) ProcessedSeriesPerWeek(ctx context.Context) (
	[]*CountPerWeek, error) {
	return readEntities[CountPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Sessions.FinishedAt, WEEK) as Date,
  COUNT(*) as Count
FROM Series
JOIN Sessions ON Sessions.ID = Series.LatestSessionID
WHERE FinishedAt IS NOT NULL
GROUP BY Date
ORDER BY Date`,
	})
}

func (repo *StatsRepository) FindingsPerWeek(ctx context.Context) (
	[]*CountPerWeek, error) {
	return readEntities[CountPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Sessions.FinishedAt, WEEK) as Date,
  COUNT(*) as Count
FROM Findings
JOIN Sessions ON Sessions.ID = Findings.SessionID
GROUP BY Date
ORDER BY Date`,
	})
}

type StatusPerWeek struct {
	Date     time.Time `spanner:"Date"`
	Finished int64     `spanner:"Finished"`
	Skipped  int64     `spanner:"Skipped"`
}

func (repo *StatsRepository) SessionStatusPerWeek(ctx context.Context) (
	[]*StatusPerWeek, error) {
	return readEntities[StatusPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Sessions.FinishedAt, WEEK) as Date,
  COUNTIF(Sessions.SkipReason IS NULL) as Finished,
  COUNTIF(Sessions.SkipReason IS NOT NULL) as Skipped
FROM Series
JOIN Sessions ON Sessions.ID = Series.LatestSessionID
WHERE FinishedAt IS NOT NULL
GROUP BY Date
ORDER BY Date`,
	})
}

type DelayPerWeek struct {
	Date       time.Time `spanner:"Date"`
	DelayHours float64   `spanner:"AvgDelayHours"`
}

func (repo *StatsRepository) DelayPerWeek(ctx context.Context) (
	[]*DelayPerWeek, error) {
	return readEntities[DelayPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Sessions.StartedAt, WEEK) as Date,
  AVG(TIMESTAMP_DIFF(Sessions.StartedAt,Sessions.CreatedAt, HOUR)) as AvgDelayHours
FROM Sessions
WHERE StartedAt IS NOT NULL
GROUP BY Date
ORDER BY Date`,
	})
}
