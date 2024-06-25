// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/covermerger"
)

// TODO: move to dashAPI once tested? I'm not sure we'll benefit.

type Coverage struct {
	Namespace     string
	FilePath      string
	Repo          string
	Commit        string
	RowsProcessed int64
	DateFrom      civil.Date
	DateTo        civil.Date
	Instrumented  int64
	Covered       int64
}

func saveToSpanner(c context.Context, mergedCoverage map[string]*covermerger.MergeResult,
	repo, commit, ns string, dateFrom, dateTo civil.Date, rowsCount int64) {
	ctx := context.Background()
	client, err := spanner.NewClient(ctx, "projects/syzkaller/instances/syzbot/databases/coverage")
	if err != nil {
		panic(fmt.Sprintf("spanner.NewClient() failed: %s", err.Error()))
	}
	defer client.Close()

	mutations := []*spanner.Mutation{}
	for fileName, fileStat := range mergedCoverage {
		var instrumentedLines int64
		var coveredLines int64
		if !fileStat.FileExists {
			continue
		}
		for _, lineHitCount := range fileStat.HitCounts {
			instrumentedLines++
			if lineHitCount > 0 {
				coveredLines++
			}
		}
		var insert *spanner.Mutation
		if insert, err = spanner.InsertOrUpdateStruct("files", Coverage{
			Namespace:     ns,
			Repo:          repo,
			Commit:        commit,
			RowsProcessed: rowsCount,
			FilePath:      fileName,
			DateFrom:      dateFrom,
			DateTo:        dateTo,
			Instrumented:  instrumentedLines,
			Covered:       coveredLines,
		}); err != nil {
			panic(fmt.Sprintf("failed to spanner.InsertStruct(): %s", err.Error()))
		}
		mutations = append(mutations, insert)
		// 80k mutations is a DB limit. 7 fields * 1k records is apx 7k mutations
		// let keep this value 10x lower to have a room for indexes
		// indexes update are also counted
		if len(mutations) > 1000 {
			if _, err = client.Apply(ctx, mutations); err != nil {
				panic(fmt.Sprintf("failed to spanner.Apply(inserts): %s", err.Error()))
			}
			mutations = nil
		}
	}
	if _, err = client.Apply(ctx, mutations); err != nil {
		panic(fmt.Sprintf("failed to spanner.Apply(inserts): %s", err.Error()))
	}
}
