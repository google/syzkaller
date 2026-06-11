// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package testutil

import (
	"testing"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/google/syzkaller/pkg/coveragedb"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"github.com/stretchr/testify/require"
)

// SetupCoverageTestDB initializes a local Spanner database with the coverage schema for testing.
func SetupCoverageTestDB(t *testing.T) *spanner.Client {
	ddl, err := coveragedb.GetSchema()
	if err != nil {
		t.Fatal(err)
	}
	uri := pkgspanner.NewTestDB(t, databasepb.DatabaseDialect_POSTGRESQL, ddl)
	ctx := t.Context()
	client, err := spanner.NewClient(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// InsertCoverageData inserts mock coverage data into the database.
func InsertCoverageData(t *testing.T, client *spanner.Client, manager string,
	history *coveragedb.HistoryRecord, records []*coveragedb.FileCoverageWithLineInfo) {
	ctx := t.Context()
	var mutations []*spanner.Mutation

	// 1. Insert merge_history row
	mhMutation, err := spanner.InsertOrUpdateStruct("merge_history", history)
	require.NoError(t, err)
	mutations = append(mutations, mhMutation)

	// 2. Insert files and file_subsystems rows
	for _, rec := range records {
		type filesRecord struct {
			Session           string
			FilePath          string
			Instrumented      int64
			Covered           int64
			LinesInstrumented []int64
			HitCounts         []int64
			Manager           string
		}
		fMutation, err := spanner.InsertOrUpdateStruct("files", &filesRecord{
			Session:           history.Session,
			FilePath:          rec.Filepath,
			Instrumented:      rec.Instrumented,
			Covered:           rec.Covered,
			LinesInstrumented: rec.LinesInstrumented,
			HitCounts:         rec.HitCounts,
			Manager:           manager,
		})
		require.NoError(t, err)
		mutations = append(mutations, fMutation)

		type fileSubsystems struct {
			Namespace  string
			FilePath   string
			Subsystems []string
		}
		fsMutation, err := spanner.InsertOrUpdateStruct("file_subsystems", &fileSubsystems{
			Namespace:  history.Namespace,
			FilePath:   rec.Filepath,
			Subsystems: rec.Subsystems,
		})
		require.NoError(t, err)
		mutations = append(mutations, fsMutation)
	}

	_, err = client.Apply(ctx, mutations)
	require.NoError(t, err)
}

// InsertFunctionsData inserts mock function lines data into the database.
func InsertFunctionsData(t *testing.T, client *spanner.Client,
	history *coveragedb.HistoryRecord, funcs []*coveragedb.FuncLines) {
	ctx := t.Context()
	var mutations []*spanner.Mutation

	// 1. Insert merge_history row if it doesn't exist
	mhMutation, err := spanner.InsertOrUpdateStruct("merge_history", history)
	require.NoError(t, err)
	mutations = append(mutations, mhMutation)

	// 2. Insert functions rows
	for _, f := range funcs {
		type functionsRecord struct {
			Session  string
			FilePath string
			FuncName string
			Lines    []int64
		}
		fMutation, err := spanner.InsertOrUpdateStruct("functions", &functionsRecord{
			Session:  history.Session,
			FilePath: f.FilePath,
			FuncName: f.FuncName,
			Lines:    f.Lines,
		})
		require.NoError(t, err)
		mutations = append(mutations, fMutation)
	}

	_, err = client.Apply(ctx, mutations)
	require.NoError(t, err)
}
