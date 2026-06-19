// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestLock(t *testing.T) {
	client := setupTestDB(t)
	ctx := t.Context()

	// 1. Acquire lock successfully
	release1, err := Lock(ctx, client, "test-lock", 1*time.Second, 10*time.Second)
	require.NoError(t, err)

	// 2. Try to acquire the same lock (should fail/timeout)
	_, err = Lock(ctx, client, "test-lock", 1*time.Second, 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lock is held by")
	var lockHeldErr *ErrLockHeld
	require.True(t, errors.As(err, &lockHeldErr))
	assert.NotEmpty(t, lockHeldErr.Owner)

	// 3. Release first lock
	err = release1()
	require.NoError(t, err)

	// 4. Try acquiring again (should succeed now)
	release2, err := Lock(ctx, client, "test-lock", 1*time.Second, 10*time.Second)
	require.NoError(t, err)
	defer release2()

	// 5. Test lock timeout (steal lock)
	// We acquire a lock with a very short timeout (2 seconds)
	release3, err := Lock(ctx, client, "test-lock-timeout", 1*time.Second, 2*time.Second)
	require.NoError(t, err)
	_ = release3

	// If we try to acquire immediately, it should fail.
	_, err = Lock(ctx, client, "test-lock-timeout", 500*time.Millisecond, 2*time.Second)
	require.Error(t, err)

	// Wait for the lock to timeout (2 seconds)
	time.Sleep(2500 * time.Millisecond)

	// Now trying to acquire should succeed (stealing the lock)
	release4, err := Lock(ctx, client, "test-lock-timeout", 1*time.Second, 2*time.Second)
	require.NoError(t, err)
	defer release4()
}
