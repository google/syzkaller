// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
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
JOIN Sessions ON Sessions.ID = Findings.SessionID
WHERE SessionReports.Moderation = FALSE AND SessionReports.ReportedAt IS NOT NULL AND Sessions.JobID IS NULL
GROUP BY Date
ORDER BY Date`,
	})
}

type ReportsPerMonth struct {
	Date     time.Time `spanner:"Date"`
	Reports  int64     `spanner:"Reports"`
	Findings int64     `spanner:"Findings"`
}

func (repo *StatsRepository) ReportsPerMonth(ctx context.Context) (
	[]*ReportsPerMonth, error) {
	return readEntities[ReportsPerMonth](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(SessionReports.ReportedAt, MONTH, 'UTC') as Date,
  COUNT(DISTINCT SessionReports.ID) as Reports,
  COUNT(Findings.ID) as Findings
FROM SessionReports
JOIN Findings ON Findings.SessionID = SessionReports.SessionID
JOIN Sessions ON Sessions.ID = SessionReports.SessionID
WHERE SessionReports.Moderation = FALSE AND SessionReports.ReportedAt IS NOT NULL AND Sessions.JobID IS NULL
GROUP BY Date
ORDER BY Date DESC`,
	})
}

func (repo *StatsRepository) FindingsPerWeek(ctx context.Context) (
	[]*CountPerWeek, error) {
	return readEntities[CountPerWeek](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Sessions.FinishedAt, WEEK) as Date,
  COUNT(*) as Count
FROM Findings
JOIN Sessions ON Sessions.ID = Findings.SessionID AND Sessions.FinishedAt IS NOT NULL AND Sessions.JobID IS NULL
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
WHERE Sessions.FinishedAt IS NOT NULL AND Sessions.JobID IS NULL
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
WHERE StartedAt IS NOT NULL AND JobID IS NULL
GROUP BY Date
ORDER BY Date`,
	})
}

func (repo *StatsRepository) CountPreventedBugs(ctx context.Context, seriesID string) (int64, error) {
	type countRow struct {
		Count int64 `spanner:"Count"`
	}
	stmt := spanner.Statement{
		SQL: `SELECT COUNT(DISTINCT SessionTestSteps.FindingID) AS Count
			FROM SessionTestSteps
			JOIN Series ON SessionTestSteps.SessionID = Series.LatestSessionID
			WHERE Series.ID = @seriesID
			  AND SessionTestSteps.Target = @target
			  AND SessionTestSteps.Result = @result
			  AND SessionTestSteps.FindingID IS NOT NULL`,
		Params: map[string]any{
			"seriesID": seriesID,
			"target":   api.StepTargetPatched,
			"result":   api.StepResultPassed,
		},
	}
	row, err := readEntity[countRow](ctx, repo.client.Single(), stmt)
	if err != nil {
		return 0, err
	}
	if row == nil {
		return 0, nil
	}
	return row.Count, nil
}

type PreventedBugsStats struct {
	Date   time.Time `spanner:"Date"`
	Series int64     `spanner:"Series"`
	Bugs   int64     `spanner:"Bugs"`
}

func (repo *StatsRepository) PreventedBugsPerMonth(ctx context.Context) ([]*PreventedBugsStats, error) {
	return readEntities[PreventedBugsStats](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(Series.PublishedAt, MONTH, 'UTC') as Date,
  COUNT(Series.ID) as Series,
  SUM(SeriesStats.PreventedBugs) as Bugs
FROM Series
JOIN SeriesStats ON SeriesStats.ID = Series.ID
WHERE SeriesStats.PreventedBugs > 0
GROUP BY Date
ORDER BY Date`,
	})
}

type JobsPerMonth struct {
	Date  time.Time `spanner:"Date"`
	Count int64     `spanner:"Count"`
}

func (repo *StatsRepository) JobsServedPerMonth(ctx context.Context) ([]*JobsPerMonth, error) {
	return readEntities[JobsPerMonth](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT
  TIMESTAMP_TRUNC(CreatedAt, MONTH, 'UTC') as Date,
  COUNT(*) as Count
FROM Jobs
GROUP BY Date
ORDER BY Date DESC`,
	})
}
