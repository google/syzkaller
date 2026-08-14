// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
)

type MonthlyModelTokenStat struct {
	Model       string
	Month       time.Time
	TotalTokens int64
}

type MonthlyJobTypeTokenStat struct {
	Type        string
	Month       time.Time
	TotalTokens int64
}

type MonthlyFinishedJobsStat struct {
	Month         time.Time
	FinishedCount int64
}

type MonthlyJobTypeStat struct {
	Type  string
	Month time.Time
	Count int64
}

func LoadMonthlyModelTokenStats(ctx context.Context, namespace string) ([]*MonthlyModelTokenStat, error) {
	return selectAll[MonthlyModelTokenStat](ctx, spanner.Statement{
		SQL: `SELECT
			COALESCE(TrajectorySpans.Model, 'unknown') AS Model,
			TIMESTAMP_TRUNC(TrajectorySpans.Started, MONTH) AS Month,
			SUM(
				COALESCE(TrajectorySpans.InputTokens, 0) +
				COALESCE(TrajectorySpans.OutputTokens, 0) +
				COALESCE(TrajectorySpans.OutputThoughtsTokens, 0)
			) AS TotalTokens
		FROM TrajectorySpans
		JOIN Jobs ON TrajectorySpans.JobID = Jobs.ID
		WHERE TrajectorySpans.Type = 'llm'
		  AND (@namespace = '' OR Jobs.Namespace = @namespace)
		GROUP BY Model, Month
		ORDER BY Month ASC`,
		Params: map[string]any{"namespace": namespace},
	})
}

func LoadMonthlyJobTypeTokenStats(ctx context.Context, namespace string) ([]*MonthlyJobTypeTokenStat, error) {
	return selectAll[MonthlyJobTypeTokenStat](ctx, spanner.Statement{
		SQL: `SELECT
			Jobs.Type AS Type,
			TIMESTAMP_TRUNC(TrajectorySpans.Started, MONTH) AS Month,
			SUM(
				COALESCE(TrajectorySpans.InputTokens, 0) +
				COALESCE(TrajectorySpans.OutputTokens, 0) +
				COALESCE(TrajectorySpans.OutputThoughtsTokens, 0)
			) AS TotalTokens
		FROM TrajectorySpans
		JOIN Jobs ON TrajectorySpans.JobID = Jobs.ID
		WHERE TrajectorySpans.Type = 'llm'
		  AND (@namespace = '' OR Jobs.Namespace = @namespace)
		GROUP BY Type, Month
		ORDER BY Month ASC`,
		Params: map[string]any{"namespace": namespace},
	})
}

func LoadMonthlyFinishedJobsStats(ctx context.Context, namespace string) ([]*MonthlyFinishedJobsStat, error) {
	return selectAll[MonthlyFinishedJobsStat](ctx, spanner.Statement{
		SQL: `SELECT
			TIMESTAMP_TRUNC(Finished, MONTH) AS Month,
			COUNT(*) AS FinishedCount
		FROM Jobs
		-- Exclude jobs that failed early (e.g. due to a restart) without generating any trajectory spans.
		WHERE Finished IS NOT NULL
		  AND EXISTS (SELECT 1 FROM TrajectorySpans WHERE TrajectorySpans.JobID = Jobs.ID)
		  AND (@namespace = '' OR Namespace = @namespace)
		GROUP BY Month
		ORDER BY Month ASC`,
		Params: map[string]any{"namespace": namespace},
	})
}

func LoadMonthlyJobTypeStats(ctx context.Context, namespace string) ([]*MonthlyJobTypeStat, error) {
	return selectAll[MonthlyJobTypeStat](ctx, spanner.Statement{
		SQL: `SELECT
			Type,
			TIMESTAMP_TRUNC(Finished, MONTH) AS Month,
			COUNT(*) AS Count
		FROM Jobs
		-- Exclude jobs that failed early (e.g. due to a restart) without generating any trajectory spans.
		WHERE Finished IS NOT NULL
		  AND EXISTS (SELECT 1 FROM TrajectorySpans WHERE TrajectorySpans.JobID = Jobs.ID)
		  AND (@namespace = '' OR Namespace = @namespace)
		GROUP BY Type, Month
		ORDER BY Month ASC`,
		Params: map[string]any{"namespace": namespace},
	})
}
