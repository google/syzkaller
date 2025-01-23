// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"google.golang.org/api/iterator"
)

// This file contains definitions of entities stored in spanner.

type CoverageHistory struct {
	instrumented map[string]int64
	covered      map[string]int64
	periods      map[coveragedb.TimePeriod]struct{}
}

// MergedCoverage uses dates, not time.
func MergedCoverage(ctx context.Context, client spannerclient.SpannerClient, ns, periodType string,
) (*CoverageHistory, error) {
	minDays, maxDays, err := coveragedb.MinMaxDays(periodType)
	if err != nil {
		return nil, fmt.Errorf("coveragedb.MinMaxDays: %w", err)
	}
	pOps, err := coveragedb.PeriodOps(periodType)
	if err != nil {
		return nil, fmt.Errorf("coveragedb.PeriodOps: %w", err)
	}
	stmt := spanner.Statement{
		SQL: `
select
  dateto as targetdate,
  duration as days,
  cast(sum(instrumented) as INTEGER) as instrumented,
  cast(sum(covered) as INTEGER) as covered
from merge_history join files
  on merge_history.session = files.session
where namespace=$1 and duration>=$2 and duration<=$3
group by dateto, duration`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": minDays,
			"p3": maxDays,
		},
	}

	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	res := &CoverageHistory{
		instrumented: map[string]int64{},
		covered:      map[string]int64{},
		periods:      map[coveragedb.TimePeriod]struct{}{},
	}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iter.Next() spanner DB: %w", err)
		}
		var r struct {
			Targetdate   civil.Date
			Days         int64
			Instrumented int64
			Covered      int64
		}
		if err = row.ToStruct(&r); err != nil {
			return nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
		}
		period := coveragedb.TimePeriod{DateTo: r.Targetdate, Days: int(r.Days)}
		if !pOps.IsValidPeriod(period) {
			continue
		}
		res.instrumented[r.Targetdate.String()] = r.Instrumented
		res.covered[r.Targetdate.String()] = r.Covered
		if _, found := res.periods[period]; found {
			return nil, fmt.Errorf("db error: only one period expected for date %s, days %d",
				period.DateTo.String(), period.Days)
		}
		res.periods[period] = struct{}{}
	}
	return res, nil
}
