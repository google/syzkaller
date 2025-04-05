// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync/atomic"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

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

type MergedCoverageRecord struct {
	Manager  string
	FilePath string
	FileData *Coverage
}

type JSONLWrapper struct {
	MCR *MergedCoverageRecord
	FL  *FuncLines
}

type Coverage struct {
	Instrumented      int64
	Covered           int64
	LinesInstrumented []int64
	HitCounts         []int64
}

func (c *Coverage) AddLineHitCount(line int, hitCount int64) {
	c.Instrumented++
	c.LinesInstrumented = append(c.LinesInstrumented, int64(line))
	c.HitCounts = append(c.HitCounts, hitCount)
	if hitCount > 0 {
		c.Covered++
	}
}

type filesRecord struct {
	Session           string
	FilePath          string
	Instrumented      int64
	Covered           int64
	LinesInstrumented []int64
	HitCounts         []int64
	Manager           string // "*" means "collected from all managers"
}

type functionsRecord struct {
	Session  string
	FilePath string
	FuncName string
	Lines    []int64
}

type fileSubsystems struct {
	Namespace  string
	FilePath   string
	Subsystems []string
}

func SaveMergeResult(ctx context.Context, client spannerclient.SpannerClient, descr *HistoryRecord, dec *json.Decoder,
	sss []*subsystem.Subsystem) (int, error) {
	if client == nil {
		return 0, fmt.Errorf("nil spannerclient")
	}
	var rowsCreated int
	ssMatcher := subsystem.MakePathMatcher(sss)
	ssCache := make(map[string][]string)

	session := uuid.New().String()
	var mutations []*spanner.Mutation

	for {
		var wr JSONLWrapper
		err := dec.Decode(&wr)
		if err == io.EOF {
			break
		}
		if err != nil {
			return rowsCreated, fmt.Errorf("dec.Decode(MergedCoverageRecord): %w", err)
		}
		if mcr := wr.MCR; mcr != nil {
			mutations = append(mutations, fileRecordMutation(session, mcr))
			subsystems := getFileSubsystems(mcr.FilePath, ssMatcher, ssCache)
			mutations = append(mutations, fileSubsystemsMutation(descr.Namespace, mcr.FilePath, subsystems))
		} else if fl := wr.FL; fl != nil {
			mutations = append(mutations, fileFunctionsMutation(session, fl))
		} else {
			return rowsCreated, errors.New("JSONLWrapper can't be empty")
		}
		// There is a limit on the number of mutations per transaction (80k) imposed by the DB.
		// This includes both explicit mutations of the fields (6 fields * 1k records = 6k mutations)
		//   and implicit index mutations.
		// We keep the number of records low enough for the number of explicit mutations * 10 does not exceed the limit.
		if len(mutations) >= 1000 {
			if _, err := client.Apply(ctx, mutations); err != nil {
				return rowsCreated, fmt.Errorf("failed to spanner.Apply(inserts): %s", err.Error())
			}
			rowsCreated += len(mutations)
			mutations = nil
		}
	}

	mutations = append(mutations, historyMutation(session, descr))
	if _, err := client.Apply(ctx, mutations); err != nil {
		return rowsCreated, fmt.Errorf("failed to spanner.Apply(inserts): %s", err.Error())
	}
	rowsCreated += len(mutations)
	return rowsCreated, nil
}

type LinesCoverage struct {
	LinesInstrumented []int64
	HitCounts         []int64
}

func linesCoverageStmt(ns, filepath, commit, manager string, timePeriod TimePeriod) spanner.Statement {
	if manager == "" {
		manager = "*"
	}
	return spanner.Statement{
		SQL: `
select
	linesinstrumented,
	hitcounts
from merge_history
	join files
		on merge_history.session = files.session
where
	namespace=$1 and dateto=$2 and duration=$3 and filepath=$4 and commit=$5 and manager=$6`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
			"p4": filepath,
			"p5": commit,
			"p6": manager,
		},
	}
}

func ReadLinesHitCount(ctx context.Context, client spannerclient.SpannerClient,
	ns, commit, file, manager string, tp TimePeriod,
) ([]int64, []int64, error) {
	stmt := linesCoverageStmt(ns, file, commit, manager, tp)
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("iter.Next: %w", err)
	}
	var r LinesCoverage
	if err = row.ToStruct(&r); err != nil {
		return nil, nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
	}
	if _, err := iter.Next(); err != iterator.Done {
		return nil, nil, fmt.Errorf("more than 1 line is available")
	}
	return r.LinesInstrumented, r.HitCounts, nil
}

func historyMutation(session string, template *HistoryRecord) *spanner.Mutation {
	historyInsert, err := spanner.InsertOrUpdateStruct("merge_history", &HistoryRecord{
		Session:   session,
		Time:      time.Now(),
		Namespace: template.Namespace,
		Repo:      template.Repo,
		Commit:    template.Commit,
		Duration:  template.Duration,
		DateTo:    template.DateTo,
		TotalRows: template.TotalRows,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to spanner.InsertStruct(): %s", err.Error()))
	}
	return historyInsert
}

func fileFunctionsMutation(session string, fl *FuncLines) *spanner.Mutation {
	insert, err := spanner.InsertOrUpdateStruct("functions", &functionsRecord{
		Session:  session,
		FilePath: fl.FilePath,
		FuncName: fl.FuncName,
		Lines:    fl.Lines,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to fileFunctionsMutation: %v", err))
	}
	return insert
}

func fileRecordMutation(session string, mcr *MergedCoverageRecord) *spanner.Mutation {
	insert, err := spanner.InsertOrUpdateStruct("files", &filesRecord{
		Session:           session,
		FilePath:          mcr.FilePath,
		Instrumented:      mcr.FileData.Instrumented,
		Covered:           mcr.FileData.Covered,
		LinesInstrumented: mcr.FileData.LinesInstrumented,
		HitCounts:         mcr.FileData.HitCounts,
		Manager:           mcr.Manager,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to fileRecordMutation: %v", err))
	}
	return insert
}

func fileSubsystemsMutation(ns, filePath string, subsystems []string) *spanner.Mutation {
	insert, err := spanner.InsertOrUpdateStruct("file_subsystems", &fileSubsystems{
		Namespace:  ns,
		FilePath:   filePath,
		Subsystems: subsystems,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to fileSubsystemsMutation(): %s", err.Error()))
	}
	return insert
}

func getFileSubsystems(filePath string, ssMatcher *subsystem.PathMatcher, ssCache map[string][]string) []string {
	sss, cached := ssCache[filePath]
	if !cached {
		for _, match := range ssMatcher.Match(filePath) {
			sss = append(sss, match.Name)
		}
		ssCache[filePath] = sss
	}
	return sss
}

func NsDataMerged(ctx context.Context, client spannerclient.SpannerClient, ns string,
) ([]TimePeriod, []int64, error) {
	if client == nil {
		return nil, nil, fmt.Errorf("nil spannerclient")
	}
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
func DeleteGarbage(ctx context.Context, client spannerclient.SpannerClient) (int64, error) {
	batchSize := 10_000
	if client == nil {
		return 0, fmt.Errorf("nil spannerclient")
	}

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
	if err := eg.Wait(); err != nil {
		return 0, fmt.Errorf("spanner.Delete: %w", err)
	}
	return totalDeleted.Load(), nil
}

func goSpannerDelete(ctx context.Context, batch []spanner.Key, eg *errgroup.Group, client spannerclient.SpannerClient,
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

type FileCoverageWithDetails struct {
	Subsystem    string
	Filepath     string
	Instrumented int64
	Covered      int64
	TimePeriod   TimePeriod `spanner:"-"`
	Commit       string
	Subsystems   []string
}

type FileCoverageWithLineInfo struct {
	FileCoverageWithDetails
	LinesInstrumented []int64
	HitCounts         []int64
}

func (fc *FileCoverageWithLineInfo) CovMap() map[int]int64 {
	return MakeCovMap(fc.LinesInstrumented, fc.HitCounts)
}

func MakeCovMap(keys, vals []int64) map[int]int64 {
	res := map[int]int64{}
	for i, key := range keys {
		res[int(key)] = vals[i]
	}
	return res
}

type SelectScope struct {
	Ns        string
	Subsystem string
	Manager   string
	Periods   []TimePeriod
}

// FilesCoverageStream streams information about all the line coverage.
// It is expensive and better to be used for time insensitive operations.
func FilesCoverageStream(ctx context.Context, client spannerclient.SpannerClient, ns string, timePeriod TimePeriod,
) (<-chan *FileCoverageWithLineInfo, <-chan error) {
	iter := client.Single().Query(ctx,
		filesCoverageWithDetailsStmt(ns, "", "", timePeriod, true))
	resCh := make(chan *FileCoverageWithLineInfo)
	errCh := make(chan error)
	go func() {
		defer close(errCh)
		defer close(resCh)
		defer iter.Stop()
		if err := readIterToChan(ctx, iter, resCh); err != nil {
			errCh <- fmt.Errorf("readIterToChan: %w", err)
		}
	}()
	return resCh, errCh
}

// FilesCoverageWithDetails fetches the data directly from DB. No caching.
// Flag onlyUnique is quite expensive.
func FilesCoverageWithDetails(
	ctx context.Context, client spannerclient.SpannerClient, scope *SelectScope, onlyUnique bool,
) ([]*FileCoverageWithDetails, error) {
	var res []*FileCoverageWithDetails
	for _, timePeriod := range scope.Periods {
		needLinesDetails := onlyUnique
		iterManager := client.Single().Query(ctx,
			filesCoverageWithDetailsStmt(scope.Ns, scope.Subsystem, scope.Manager, timePeriod, needLinesDetails))
		defer iterManager.Stop()

		var err error
		var periodRes []*FileCoverageWithDetails
		if onlyUnique {
			iterAll := client.Single().Query(ctx,
				filesCoverageWithDetailsStmt(scope.Ns, scope.Subsystem, "", timePeriod, needLinesDetails))
			defer iterAll.Stop()
			periodRes, err = readCoverageUniq(iterAll, iterManager)
			if err != nil {
				return nil, fmt.Errorf("uniqueFilesCoverageWithDetails: %w", err)
			}
		} else {
			periodRes, err = readCoverage(ctx, iterManager)
			if err != nil {
				return nil, fmt.Errorf("readCoverage: %w", err)
			}
		}
		for _, r := range periodRes {
			r.TimePeriod = timePeriod
		}
		res = append(res, periodRes...)
	}
	return res, nil
}

func filesCoverageWithDetailsStmt(ns, subsystem, manager string, timePeriod TimePeriod, withLines bool,
) spanner.Statement {
	if manager == "" {
		manager = "*"
	}
	selectColumns := "commit, instrumented, covered, files.filepath, subsystems"
	if withLines {
		selectColumns += ", linesinstrumented, hitcounts"
	}
	stmt := spanner.Statement{
		SQL: "select " + selectColumns + `
from merge_history
  join files
    on merge_history.session = files.session
  join file_subsystems
    on merge_history.namespace = file_subsystems.namespace and files.filepath = file_subsystems.filepath
where
  merge_history.namespace=$1 and dateto=$2 and duration=$3 and manager=$4`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
			"p4": manager,
		},
	}
	if subsystem != "" {
		stmt.SQL += " and $5=ANY(subsystems)"
		stmt.Params["p5"] = subsystem
	}
	stmt.SQL += "\norder by files.filepath"
	return stmt
}

func readCoverage(ctx context.Context, iterManager spannerclient.RowIterator) ([]*FileCoverageWithDetails, error) {
	res := []*FileCoverageWithDetails{}
	ch := make(chan *FileCoverageWithDetails)
	var err error
	go func() {
		defer close(ch)
		err = readIterToChan(ctx, iterManager, ch)
	}()
	for fc := range ch {
		res = append(res, fc)
	}
	if err != nil {
		return nil, fmt.Errorf("readIterToChan: %w", err)
	}
	return res, nil
}

// Unique coverage from specific manager is more expensive to get.
// We get unique coverage comparing manager and total coverage on the AppEngine side.
func readCoverageUniq(full, mgr spannerclient.RowIterator,
) ([]*FileCoverageWithDetails, error) {
	eg, ctx := errgroup.WithContext(context.Background())
	fullCh := make(chan *FileCoverageWithLineInfo)
	eg.Go(func() error {
		defer close(fullCh)
		return readIterToChan(ctx, full, fullCh)
	})
	partCh := make(chan *FileCoverageWithLineInfo)
	eg.Go(func() error {
		defer close(partCh)
		return readIterToChan(ctx, mgr, partCh)
	})
	res := []*FileCoverageWithDetails{}
	eg.Go(func() error {
		partCov := <-partCh
		for fullCov := range fullCh {
			if partCov == nil || partCov.Filepath > fullCov.Filepath {
				// No pair for the file in full aggregation is available.
				cov := fullCov.FileCoverageWithDetails
				cov.Covered = 0
				res = append(res, &cov)
				continue
			}
			if partCov.Filepath == fullCov.Filepath {
				if partCov.Commit != fullCov.Commit ||
					!IsComparable(
						fullCov.LinesInstrumented, fullCov.HitCounts,
						partCov.LinesInstrumented, partCov.HitCounts) {
					return fmt.Errorf("db record for file %s doesn't match", fullCov.Filepath)
				}
				resItem := fullCov.FileCoverageWithDetails // Use Instrumented count from full aggregation.
				resItem.Covered = 0
				for _, hc := range UniqCoverage(fullCov.CovMap(), partCov.CovMap()) {
					if hc > 0 {
						resItem.Covered++
					}
				}
				res = append(res, &resItem)
				partCov = <-partCh
				continue
			}
			// Partial coverage is a subset of full coverage.
			// File can't exist only in partial set.
			return fmt.Errorf("currupted db, file %s can't exist", partCov.Filepath)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("eg.Wait: %w", err)
	}
	return res, nil
}

func readIterToChan[K FileCoverageWithLineInfo | FileCoverageWithDetails](
	ctx context.Context, iter spannerclient.RowIterator, ch chan<- *K) error {
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("iter.Next: %w", err)
		}
		var r K
		if err = row.ToStruct(&r); err != nil {
			return fmt.Errorf("row.ToStruct: %w", err)
		}
		select {
		case ch <- &r:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func IsComparable(fullLines, fullHitCounts, partialLines, partialHitCounts []int64) bool {
	if len(fullLines) != len(fullHitCounts) ||
		len(partialLines) != len(partialHitCounts) ||
		len(fullLines) < len(partialLines) {
		return false
	}
	fullCov := MakeCovMap(fullLines, fullHitCounts)
	for iPartial, ln := range partialLines {
		partialHitCount := partialHitCounts[iPartial]
		if fullHitCount, fullExist := fullCov[int(ln)]; !fullExist || fullHitCount < partialHitCount {
			return false
		}
	}
	return true
}

// Returns partial hitcounts that are the only source of the full hitcounts.
func UniqCoverage(fullCov, partCov map[int]int64) map[int]int64 {
	res := maps.Clone(partCov)
	for ln := range partCov {
		if partCov[ln] != fullCov[ln] {
			res[ln] = 0
		}
	}
	return res
}
