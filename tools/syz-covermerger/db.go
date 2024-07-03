// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
)

// TODO: move to dashAPI once tested? I'm not sure we'll benefit.

type DBRecord struct {
	Namespace    string
	Repo         string
	Commit       string
	Duration     int64
	DateTo       civil.Date
	FilePath     string
	Instrumented int64
	Covered      int64
}

type DBHistoryRecord struct {
	Namespace string
	Repo      string
	Commit    string
	Duration  int64
	DateTo    civil.Date
	TotalRows int64
}

func saveToSpanner(ctx context.Context, projectID string, coverage map[string]*Coverage,
	template *DBRecord, totalRows int64) {
	client, err := spanner.NewClient(ctx, "projects/"+projectID+"/instances/syzbot/databases/coverage")
	if err != nil {
		panic(fmt.Sprintf("spanner.NewClient() failed: %s", err.Error()))
	}
	defer client.Close()

	mutations := []*spanner.Mutation{}
	for filePath, record := range coverage {
		var insert *spanner.Mutation
		if insert, err = spanner.InsertOrUpdateStruct("files", &DBRecord{
			Namespace:    template.Namespace,
			Repo:         template.Repo,
			Commit:       template.Commit,
			Duration:     template.Duration,
			DateTo:       template.DateTo,
			FilePath:     filePath,
			Instrumented: record.Instrumented,
			Covered:      record.Covered,
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

	var historyInsert *spanner.Mutation
	if historyInsert, err = spanner.InsertOrUpdateStruct("merge_history", &DBHistoryRecord{
		Namespace: template.Namespace,
		Repo:      template.Repo,
		Commit:    template.Commit,
		Duration:  template.Duration,
		DateTo:    template.DateTo,
		TotalRows: totalRows,
	}); err != nil {
		panic(fmt.Sprintf("failed to spanner.InsertStruct(): %s", err.Error()))
	}
	mutations = append(mutations, historyInsert)

	if _, err = client.Apply(ctx, mutations); err != nil {
		panic(fmt.Sprintf("failed to spanner.Apply(inserts): %s", err.Error()))
	}
}
