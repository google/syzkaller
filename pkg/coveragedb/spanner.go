// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

type FilesRecord struct {
	Session           string
	FilePath          string
	Instrumented      int64
	Covered           int64
	LinesInstrumented []int64
	HitCounts         []int64
}

type FileSubsystems struct {
	Namespace  string
	FilePath   string
	Subsystems []string
}

type HistoryRecord struct {
	Session   string
	Time      time.Time
	Namespace string
	Repo      string
	Commit    string
	Duration  int64
	DateTo    civil.Date
	TotalRows int64
}

func NewClient(ctx context.Context, projectID string) (*spanner.Client, error) {
	database := "projects/" + projectID + "/instances/syzbot/databases/coverage"
	return spanner.NewClient(ctx, database)
}

type Coverage struct {
	Instrumented      int64
	Covered           int64
	LinesInstrumented []int64
	HitCounts         []int64
}

func SaveMergeResult(ctx context.Context, projectID string, covMap map[string]*Coverage,
	template *HistoryRecord, totalRows int64, sss []*subsystem.Subsystem) error {
	client, err := NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("spanner.NewClient() failed: %s", err.Error())
	}
	defer client.Close()

	ssMatcher := subsystem.MakePathMatcher(sss)
	ssCache := make(map[string][]string)

	session := uuid.New().String()
	mutations := []*spanner.Mutation{}
	for filePath, record := range covMap {
		mutations = append(mutations, fileRecordMutation(session, filePath, record))
		subsystems := fileSubsystems(filePath, ssMatcher, ssCache)
		mutations = append(mutations, fileSubsystemsMutation(template.Namespace, filePath, subsystems))
		// There is a limit on the number of mutations per transaction (80k) imposed by the DB.
		// This includes both explicit mutations of the fields (6 fields * 1k records = 6k mutations)
		//   and implicit index mutations.
		// We keep the number of records low enough for the number of explicit mutations * 10 does not exceed the limit.
		if len(mutations) > 1000 {
			if _, err = client.Apply(ctx, mutations); err != nil {
				return fmt.Errorf("failed to spanner.Apply(inserts): %s", err.Error())
			}
			mutations = nil
		}
	}
	mutations = append(mutations, historyMutation(session, template, totalRows))
	if _, err = client.Apply(ctx, mutations); err != nil {
		return fmt.Errorf("failed to spanner.Apply(inserts): %s", err.Error())
	}
	return nil
}

type linesCoverage struct {
	LinesInstrumented []int64
	HitCounts         []int64
}

func linesCoverageStmt(ns, filepath, commit string, timePeriod TimePeriod) spanner.Statement {
	return spanner.Statement{
		SQL: `
select
	linesinstrumented,
	hitcounts
from merge_history
	join files
		on merge_history.session = files.session
where
	namespace=$1 and dateto=$2 and duration=$3 and filepath=$4 and commit=$5`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
			"p4": filepath,
			"p5": commit,
		},
	}
}

func ReadLinesHitCount(ctx context.Context, ns, commit, file string, tp TimePeriod,
) (map[int]int, error) {
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	client, err := NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("spanner.NewClient: %w", err)
	}
	defer client.Close()

	stmt := linesCoverageStmt(ns, file, commit, tp)
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("iter.Next: %w", err)
	}
	var r linesCoverage
	if err = row.ToStruct(&r); err != nil {
		return nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
	}

	res := map[int]int{}
	for i, instrLine := range r.LinesInstrumented {
		res[int(instrLine)] = int(r.HitCounts[i])
	}
	return res, nil
}

func historyMutation(session string, template *HistoryRecord, totalRows int64) *spanner.Mutation {
	historyInsert, err := spanner.InsertOrUpdateStruct("merge_history", &HistoryRecord{
		Session:   session,
		Time:      time.Now(),
		Namespace: template.Namespace,
		Repo:      template.Repo,
		Commit:    template.Commit,
		Duration:  template.Duration,
		DateTo:    template.DateTo,
		TotalRows: totalRows,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to spanner.InsertStruct(): %s", err.Error()))
	}
	return historyInsert
}

func fileRecordMutation(session, filePath string, record *Coverage) *spanner.Mutation {
	insert, err := spanner.InsertOrUpdateStruct("files", &FilesRecord{
		Session:           session,
		FilePath:          filePath,
		Instrumented:      record.Instrumented,
		Covered:           record.Covered,
		LinesInstrumented: record.LinesInstrumented,
		HitCounts:         record.HitCounts,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to fileRecordMutation: %v", err))
	}
	return insert
}

func fileSubsystemsMutation(ns, filePath string, subsystems []string) *spanner.Mutation {
	insert, err := spanner.InsertOrUpdateStruct("file_subsystems", &FileSubsystems{
		Namespace:  ns,
		FilePath:   filePath,
		Subsystems: subsystems,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to fileSubsystemsMutation(): %s", err.Error()))
	}
	return insert
}

func fileSubsystems(filePath string, ssMatcher *subsystem.PathMatcher, ssCache map[string][]string) []string {
	sss, cached := ssCache[filePath]
	if !cached {
		for _, match := range ssMatcher.Match(filePath) {
			sss = append(sss, match.Name)
		}
		ssCache[filePath] = sss
	}
	return sss
}

func NsDataMerged(ctx context.Context, projectID, ns string) ([]TimePeriod, []int64, error) {
	client, err := NewClient(ctx, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("spanner.NewClient() failed: %s", err.Error())
	}
	defer client.Close()

	stmt := spanner.Statement{
		SQL: `
			select
				dateto,
				duration as days,
				totalrows
			from merge_history
			where
				namespace=$1`,
		Params: map[string]interface{}{
			"p1": ns,
		},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	var periods []TimePeriod
	var totalRows []int64
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to iter.Next() spanner DB: %w", err)
		}
		var r struct {
			Days      int64
			DateTo    civil.Date
			TotalRows int64
		}
		if err = row.ToStruct(&r); err != nil {
			return nil, nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
		}
		periods = append(periods, TimePeriod{DateTo: r.DateTo, Days: int(r.Days)})
		totalRows = append(totalRows, r.TotalRows)
	}
	return periods, totalRows, nil
}

// DeleteGarbage removes orphaned file entries from the database.
//
// It identifies files in the "files" table that are not referenced by any entries in the "merge_history" table,
// indicating they are no longer associated with an active merge session.
//
// To avoid exceeding Spanner transaction limits, orphaned files are deleted in batches of 10,000.
// Note that in case of an error during batch deletion, some files may be deleted but not counted in the total.
//
// Returns the number of orphaned file entries successfully deleted.
func DeleteGarbage(ctx context.Context) (int64, error) {
	batchSize := 10_000
	client, err := NewClient(ctx, os.Getenv("GOOGLE_CLOUD_PROJECT"))
	if err != nil {
		return 0, fmt.Errorf("coveragedb.NewClient: %w", err)
	}
	defer client.Close()

	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT session, filepath
					FROM files
					WHERE NOT EXISTS (
						SELECT 1
						FROM merge_history
						WHERE merge_history.session = files.session
					)`})
	defer iter.Stop()

	var totalDeleted atomic.Int64
	eg, _ := errgroup.WithContext(ctx)
	var batch []spanner.Key
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("iter.Next: %w", err)
		}
		var r struct {
			Session  string
			Filepath string
		}
		if err = row.ToStruct(&r); err != nil {
			return 0, fmt.Errorf("row.ToStruct: %w", err)
		}
		batch = append(batch, spanner.Key{r.Session, r.Filepath})
		if len(batch) > batchSize {
			goSpannerDelete(ctx, batch, eg, client, &totalDeleted)
			batch = nil
		}
	}
	goSpannerDelete(ctx, batch, eg, client, &totalDeleted)
	if err = eg.Wait(); err != nil {
		return 0, fmt.Errorf("spanner.Delete: %w", err)
	}
	return totalDeleted.Load(), nil
}

func goSpannerDelete(ctx context.Context, batch []spanner.Key, eg *errgroup.Group, client *spanner.Client,
	totalDeleted *atomic.Int64) {
	ks := spanner.KeySetFromKeys(batch...)
	ksSize := len(batch)
	eg.Go(func() error {
		mutation := spanner.Delete("files", ks)
		_, err := client.Apply(ctx, []*spanner.Mutation{mutation})
		if err == nil {
			totalDeleted.Add(int64(ksSize))
		}
		return err
	})
}
