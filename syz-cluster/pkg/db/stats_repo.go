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

func (repo *StatsRepository) ReportsPerWeek(ctx context.Context) (
	[]*CountPerWeek, error) {
	return readEntities[CountPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(SessionReports.ReportedAt, WEEK) as Date,
  COUNT(*) as Count
FROM Findings
JOIN SessionReports ON SessionReports.SessionID = Findings.SessionID
WHERE SessionReports.Moderation = FALSE AND SessionReports.ReportedAt IS NOT NULL
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
JOIN Sessions ON Sessions.ID = Findings.SessionID AND Sessions.FinishedAt IS NOT NULL
GROUP BY Date
ORDER BY Date`,
	})
}

type StatusPerWeek struct {
	Date             time.Time `spanner:"Date"`
	Total            int64     `spanner:"Total"`
	Finished         int64
	Skipped          int64 `spanner:"Skipped"`
	WithFailedSteps  int64 `spanner:"WithFailedSteps"`
	WithSkippedSteps int64 `spanner:"WithSkippedSteps"`
}

func (repo *StatsRepository) SessionStatusPerWeek(ctx context.Context) (
	[]*StatusPerWeek, error) {
	rows, err := readEntities[StatusPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `WITH SessionTestAggregates AS (
  SELECT
    SessionID,
    COUNTIF(Result = 'error') > 0 AS HasFailedSteps,
    COUNTIF(Result = 'skipped') > 0 AS HasSkippedSteps
  FROM SessionTests
  GROUP BY SessionID
)
SELECT
  TIMESTAMP_TRUNC(Sessions.FinishedAt, WEEK) AS Date,
  COUNT(Sessions.ID) AS Total,
  COUNTIF(Sessions.SkipReason IS NOT NULL) AS Skipped,
  COUNTIF(sta.HasFailedSteps) AS WithFailedSteps,
  COUNTIF(sta.HasSkippedSteps AND NOT sta.HasFailedSteps) AS WithSkippedSteps
FROM Sessions
LEFT JOIN
  SessionTestAggregates AS sta ON Sessions.ID = sta.SessionID
WHERE Sessions.FinishedAt IS NOT NULL
GROUP BY Date
ORDER BY Date`,
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		row.Finished = row.Total - row.Skipped - row.WithFailedSteps - row.WithSkippedSteps
	}
	return rows, err
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
