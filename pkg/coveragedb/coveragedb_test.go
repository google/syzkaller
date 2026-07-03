// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func setupTestDB(t *testing.T) *spanner.Client {
	ddl, err := GetSchema()
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

func insertCoverage(t *testing.T, client *spanner.Client, manager string,
	history *HistoryRecord, records []*FileCoverageWithLineInfo) {
	ctx := t.Context()
	var mutations []*spanner.Mutation

	// 1. Insert merge_history row
	mhMutation, err := spanner.InsertOrUpdateStruct("merge_history", history)
	require.NoError(t, err)
	mutations = append(mutations, mhMutation)

	// 2. Insert files and file_subsystems rows
	for _, rec := range records {
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

func TestFilesCoverageWithDetails(t *testing.T) {
	period, _ := MakeTimePeriod(
		civil.Date{Year: 2025, Month: 1, Day: 1},
		"day")

	t.Run("empty scope", func(t *testing.T) {
		client := setupTestDB(t)
		got, err := FilesCoverageWithDetails(t.Context(), client, &SelectScope{}, false)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("empty DB => no coverage", func(t *testing.T) {
		for _, onlyUnique := range []bool{false, true} {
			client := setupTestDB(t)
			scope := &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			}
			got, err := FilesCoverageWithDetails(t.Context(), client, scope, onlyUnique)
			require.NoError(t, err)
			require.Empty(t, got)
		}
	})

	t.Run("single day, unique coverage, empty partial result => 0/3 covered", func(t *testing.T) {
		client := setupTestDB(t)
		ns := "upstream"
		scope := &SelectScope{
			Ns:      ns,
			Periods: []TimePeriod{period},
			Manager: "manager1",
		}
		// Insert full coverage.
		histFull := &HistoryRecord{
			Namespace: ns,
			Repo:      "repo-full",
			Duration:  int64(period.Days),
			DateTo:    period.DateTo,
			Session:   "session-full",
			Time:      time.Now(),
			Commit:    "commit1",
			TotalRows: 100,
		}
		insertCoverage(t, client, "*", histFull, []*FileCoverageWithLineInfo{
			{
				FileCoverageWithDetails: FileCoverageWithDetails{
					Filepath:     "file1",
					Instrumented: 3,
					Covered:      3,
					Subsystems:   []string{"sub1"},
				},
				LinesInstrumented: []int64{1, 2, 3},
				HitCounts:         []int64{1, 1, 1},
			},
		})
		// Insert partial coverage (empty partial result means no records for manager1).
		// So we do not insert anything for manager1.

		got, err := FilesCoverageWithDetails(t.Context(), client, scope, true)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "file1", got[0].Filepath)
		assert.Equal(t, int64(3), got[0].Instrumented)
		assert.Equal(t, int64(0), got[0].Covered)
		assert.Equal(t, period, got[0].TimePeriod)
	})

	t.Run("single day, unique coverage, full result match => 3/3 covered", func(t *testing.T) {
		client := setupTestDB(t)
		ns := "upstream"
		scope := &SelectScope{
			Ns:      ns,
			Periods: []TimePeriod{period},
			Manager: "manager1",
		}
		fullRec := []*FileCoverageWithLineInfo{
			{
				FileCoverageWithDetails: FileCoverageWithDetails{
					Filepath:     "file1",
					Instrumented: 3,
					Covered:      3,
					Subsystems:   []string{"sub1"},
				},
				LinesInstrumented: []int64{1, 2, 3},
				HitCounts:         []int64{1, 1, 1},
			},
		}
		// Insert full.
		histFull := &HistoryRecord{
			Namespace: ns,
			Repo:      "repo-full",
			Duration:  int64(period.Days),
			DateTo:    period.DateTo,
			Session:   "session-full",
			Time:      time.Now(),
			Commit:    "commit1",
			TotalRows: 100,
		}
		insertCoverage(t, client, "*", histFull, fullRec)
		// Insert partial (manager1 has same coverage).
		histPart := &HistoryRecord{
			Namespace: ns,
			Repo:      "repo-part",
			Duration:  int64(period.Days),
			DateTo:    period.DateTo,
			Session:   "session-part",
			Time:      time.Now(),
			Commit:    "commit1",
			TotalRows: 100,
		}
		insertCoverage(t, client, "manager1", histPart, fullRec)

		got, err := FilesCoverageWithDetails(t.Context(), client, scope, true)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "file1", got[0].Filepath)
		assert.Equal(t, int64(3), got[0].Instrumented)
		assert.Equal(t, int64(3), got[0].Covered)
		assert.Equal(t, period, got[0].TimePeriod)
	})

	t.Run("single day, unique coverage, partial result match => 3/5 covered", func(t *testing.T) {
		client := setupTestDB(t)
		ns := "upstream"
		scope := &SelectScope{
			Ns:      ns,
			Periods: []TimePeriod{period},
			Manager: "manager1",
		}
		fullRec := []*FileCoverageWithLineInfo{
			{
				FileCoverageWithDetails: FileCoverageWithDetails{
					Filepath:     "file1",
					Instrumented: 5,
					Covered:      5,
					Subsystems:   []string{"sub1"},
				},
				LinesInstrumented: []int64{1, 2, 3, 4, 5},
				HitCounts:         []int64{3, 4, 5, 6, 7},
			},
		}
		partRec := []*FileCoverageWithLineInfo{
			{
				FileCoverageWithDetails: FileCoverageWithDetails{
					Filepath:     "file1",
					Instrumented: 4,
					Covered:      3,
					Subsystems:   []string{"sub1"},
				},
				LinesInstrumented: []int64{1, 2, 3, 5},
				HitCounts:         []int64{3, 0, 5, 7},
			},
		}
		// Insert full.
		histFull := &HistoryRecord{
			Namespace: ns,
			Repo:      "repo-full",
			Duration:  int64(period.Days),
			DateTo:    period.DateTo,
			Session:   "session-full",
			Time:      time.Now(),
			Commit:    "commit1",
			TotalRows: 100,
		}
		insertCoverage(t, client, "*", histFull, fullRec)
		// Insert partial.
		histPart := &HistoryRecord{
			Namespace: ns,
			Repo:      "repo-part",
			Duration:  int64(period.Days),
			DateTo:    period.DateTo,
			Session:   "session-part",
			Time:      time.Now(),
			Commit:    "commit1",
			TotalRows: 100,
		}
		insertCoverage(t, client, "manager1", histPart, partRec)

		got, err := FilesCoverageWithDetails(t.Context(), client, scope, true)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "file1", got[0].Filepath)
		assert.Equal(t, int64(5), got[0].Instrumented)
		assert.Equal(t, int64(3), got[0].Covered)
		assert.Equal(t, period, got[0].TimePeriod)
	})
}

func TestSaveMergeResult(t *testing.T) {
	tests := []struct {
		name     string
		jsonl    string
		descr    *HistoryRecord
		wantErr  bool
		wantRows int
	}{
		{
			name:    "empty jsonl",
			jsonl:   `{}`,
			wantErr: true,
		},
		{
			name:    "wrong jsonl content",
			jsonl:   `{a}`,
			wantErr: true,
		},
		{
			name:  "1 MCR record, Ok",
			jsonl: `{"MCR":{"FileData":{}}}`,
			descr: &HistoryRecord{
				Namespace: "ns1",
				Repo:      "repo1",
				Duration:  1,
				DateTo:    civil.Date{Year: 2025, Month: 1, Day: 1},
			},
			wantRows: 2, // 1 in files and 1 in merge_history.
		},
		{
			name:  "1 FL record, Ok",
			jsonl: `{"FL":{}}`,
			descr: &HistoryRecord{
				Namespace: "ns1",
				Repo:      "repo1",
				Duration:  1,
				DateTo:    civil.Date{Year: 2025, Month: 1, Day: 1},
			},
			wantRows: 2, // 1 in functions and 1 in merge_history.
		},
		{
			name: "2 records, Ok",
			jsonl: `{"MCR":{"FileData":{}}}
{"MCR":{"FileData":{}}}`,
			descr: &HistoryRecord{
				Namespace: "ns1",
				Repo:      "repo1",
				Duration:  1,
				DateTo:    civil.Date{Year: 2025, Month: 1, Day: 1},
			},
			wantRows: 3, // 2 in files and 1 in merge_history.
		},
		{
			name:  "2k records, Ok",
			jsonl: strings.Repeat("{\"MCR\":{\"FileData\":{}}}\n", 2000),
			descr: &HistoryRecord{
				Namespace: "ns1",
				Repo:      "repo1",
				Duration:  1,
				DateTo:    civil.Date{Year: 2025, Month: 1, Day: 1},
			},
			wantRows: 2001,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := setupTestDB(t)
			gotRows, err := SaveMergeResult(
				t.Context(), client, test.descr, json.NewDecoder(strings.NewReader(test.jsonl)))
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.wantRows, gotRows)
		})
	}
}

func TestMigrations(t *testing.T) {
	// setupTestDB already ran the up statements, so we start with down.
	client := setupTestDB(t)
	uri := client.DatabaseName()

	up, err := GetSchema()
	require.NoError(t, err)
	down, err := GetDownSchema()
	require.NoError(t, err)

	ctx := t.Context()
	require.NoError(t, pkgspanner.UpdateSpannerDDL(ctx, uri, down))
	require.NoError(t, pkgspanner.UpdateSpannerDDL(ctx, uri, up))
	require.NoError(t, pkgspanner.UpdateSpannerDDL(ctx, uri, down))
	require.NoError(t, pkgspanner.UpdateSpannerDDL(ctx, uri, up))
}

func TestDeleteGarbage(t *testing.T) {
	client := setupTestDB(t)
	ctx := t.Context()

	now := time.Now()
	cutoff := now.Add(-oneWeekAgo)

	// 1. Completed session (should NOT be deleted)
	sessionCompleted := "session-completed"
	_, err := client.Apply(ctx, []*spanner.Mutation{
		spanner.Insert("sessions", []string{"session", "created"}, []any{sessionCompleted, now.Add(-2 * time.Hour)}),
		spanner.Insert("merge_history",
			[]string{"namespace", "repo", "duration", "dateto", "session", "time"},
			[]any{"ns1", "repo1", int64(1), civil.Date{Year: 2025, Month: 1, Day: 1}, sessionCompleted, now}),
		spanner.Insert("files",
			[]string{"session", "manager", "filepath", "instrumented", "covered"},
			[]any{sessionCompleted, "*", "file-completed", int64(10), int64(5)}),
		spanner.InsertOrUpdate("functions", []string{"session", "filepath", "funcname", "lines"},
			[]any{sessionCompleted, "file-completed", "func-completed", []int64{1, 2}}),
	})
	require.NoError(t, err)

	insertIncompleteSession := func(session, suffix string, created time.Time) {
		_, err = client.Apply(ctx, []*spanner.Mutation{
			spanner.Insert("sessions", []string{"session", "created"}, []any{session, created}),
			spanner.Insert("files",
				[]string{"session", "manager", "filepath", "instrumented", "covered"},
				[]any{session, "*", "file-" + suffix, int64(10), int64(5)}),
			spanner.InsertOrUpdate("functions", []string{"session", "filepath", "funcname", "lines"},
				[]any{session, "file-" + suffix, "func-" + suffix, []int64{1, 2}}),
		})
		require.NoError(t, err)
	}

	// 2. Active incomplete session (younger than 1 week, should NOT be deleted).
	sessionActive := "session-active"
	insertIncompleteSession(sessionActive, "active", now.Add(-1*time.Hour))

	// 3. Failed incomplete session (older than 1 week, should BE deleted).
	sessionFailed := "session-failed"
	insertIncompleteSession(sessionFailed, "failed", cutoff.Add(-1*time.Hour))

	// 4. Old garbage session without sessions record (should BE auto-migrated, NOT deleted yet)
	sessionOldGarbage := "session-old-garbage"
	_, err = client.Apply(ctx, []*spanner.Mutation{
		spanner.Insert("files",
			[]string{"session", "manager", "filepath", "instrumented", "covered"},
			[]any{sessionOldGarbage, "*", "file-old-garbage", int64(10), int64(5)}),
		spanner.InsertOrUpdate("functions", []string{"session", "filepath", "funcname", "lines"},
			[]any{sessionOldGarbage, "file-old-garbage", "func-old-garbage", []int64{1, 2}}),
	})
	require.NoError(t, err)

	// 5. Old garbage session with only functions record (should BE auto-migrated, NOT deleted yet)
	sessionFuncsOnly := "session-funcs-only"
	_, err = client.Apply(ctx, []*spanner.Mutation{
		spanner.InsertOrUpdate("functions", []string{"session", "filepath", "funcname", "lines"},
			[]any{sessionFuncsOnly, "file-funcs-only", "func-funcs-only", []int64{1, 2}}),
	})
	require.NoError(t, err)

	// Run DeleteGarbage.
	deletedSessions, deletedRows, err := DeleteGarbage(ctx, client)
	require.NoError(t, err)

	// We expect:
	// - sessionFailed is deleted: 1 session.
	// - deleted rows: 1 from files + 1 from functions = 2 rows.
	assert.Equal(t, int64(1), deletedSessions)
	assert.Equal(t, int64(2), deletedRows)

	// Verify DB state.
	assertRowExists(t, client, "sessions", spanner.Key{sessionCompleted})
	assertRowExists(t, client, "files", spanner.Key{sessionCompleted, "*", "file-completed"})
	assertRowExists(t, client, "functions", spanner.Key{sessionCompleted, "file-completed", "func-completed"})

	assertRowExists(t, client, "sessions", spanner.Key{sessionActive})
	assertRowExists(t, client, "files", spanner.Key{sessionActive, "*", "file-active"})
	assertRowExists(t, client, "functions", spanner.Key{sessionActive, "file-active", "func-active"})

	assertRowNotExists(t, client, "sessions", spanner.Key{sessionFailed})
	assertRowNotExists(t, client, "files", spanner.Key{sessionFailed, "*", "file-failed"})
	assertRowNotExists(t, client, "functions", spanner.Key{sessionFailed, "file-failed", "func-failed"})

	assertRowExists(t, client, "sessions", spanner.Key{sessionOldGarbage})
	assertRowExists(t, client, "files", spanner.Key{sessionOldGarbage, "*", "file-old-garbage"})
	assertRowExists(t, client, "functions", spanner.Key{sessionOldGarbage, "file-old-garbage", "func-old-garbage"})

	assertRowExists(t, client, "sessions", spanner.Key{sessionFuncsOnly})
	assertRowExists(t, client, "functions", spanner.Key{sessionFuncsOnly, "file-funcs-only", "func-funcs-only"})

	var created time.Time
	row, err := client.Single().ReadRow(ctx, "sessions", spanner.Key{sessionOldGarbage}, []string{"created"})
	require.NoError(t, err)
	err = row.Column(0, &created)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), created, 10*time.Second)
}

func assertRowExists(t *testing.T, client *spanner.Client, table string, key spanner.Key) {
	ctx := t.Context()
	row, err := client.Single().ReadRow(ctx, table, key, []string{tableColumns(table)[0]})
	require.NoError(t, err)
	require.NotNil(t, row)
}

func assertRowNotExists(t *testing.T, client *spanner.Client, table string, key spanner.Key) {
	ctx := t.Context()
	_, err := client.Single().ReadRow(ctx, table, key, []string{tableColumns(table)[0]})
	assert.True(t, spanner.ErrCode(err) == codes.NotFound, "expected NotFound error, got %v", err)
}

func tableColumns(table string) []string {
	switch table {
	case "files":
		return []string{"session", "manager", "filepath"}
	case "functions":
		return []string{"session", "filepath", "funcname"}
	case "sessions":
		return []string{"session", "created"}
	case "merge_history":
		return []string{"namespace", "repo", "duration", "dateto"}
	default:
		panic("unknown table")
	}
}
