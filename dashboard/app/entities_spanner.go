// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

// This file contains definitions of entities stored in spanner.

type CoverageHistory struct {
	instrumented map[string]int64
	covered      map[string]int64
}

// MergedCoverage uses dates, not time.
func MergedCoverage(ctx context.Context, ns string, fromDate, toDate civil.Date) (*CoverageHistory, error) {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	client, err := spanner.NewClient(ctx, "projects/"+projectID+"/instances/syzbot/databases/coverage")
	if err != nil {
		panic(fmt.Sprintf("spanner.NewClient() failed: %s", err.Error()))
	}
	defer client.Close()

	stmt := spanner.Statement{
		SQL: `select
			dateto as targetdate,
			cast(sum(instrumented) as INTEGER) as instrumented,
			cast(sum(covered) as INTEGER) as covered
		from "files"
	where namespace=$1 and dateto>=$2 and dateto<=$3
		group by targetdate`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": fromDate,
			"p3": toDate,
		},
	}

	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	res := &CoverageHistory{
		instrumented: map[string]int64{},
		covered:      map[string]int64{},
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
			Instrumented int64
			Covered      int64
		}
		if err = row.ToStruct(&r); err != nil {
			return nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
		}
		res.instrumented[r.Targetdate.String()] = r.Instrumented
		res.covered[r.Targetdate.String()] = r.Covered
	}
	return res, nil
}
