// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package coveragedb provides database storage and querying for historical coverage records.
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
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

const oneWeekAgo = 7 * 24 * time.Hour

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

func SaveMergeResult(ctx context.Context, client *spanner.Client, descr *HistoryRecord, dec *json.Decoder,
) (int, error) {
	if client == nil {
		return 0, fmt.Errorf("nil spannerclient")
	}
	var rowsCreated int
	session := uuid.New().String()
	// Register session. We need this Apply call for referential integrity.
	// GC will not be touching this session records.
	_, err := client.Apply(ctx, []*spanner.Mutation{
		spanner.Insert("sessions", []string{"session", "created"}, []any{session, time.Now()}),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to register session: %w", err)
	}

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
		Params: map[string]any{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
			"p4": filepath,
			"p5": commit,
			"p6": manager,
		},
	}
}

func ReadLinesHitCount(ctx context.Context, client *spanner.Client,
	ns, commit, file, manager string, tp TimePeriod,
) ([]int64, []int64, error) {
	stmt := linesCoverageStmt(ns, file, commit, manager, tp)
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	r, err := pkgspanner.ReadRow[LinesCoverage](iter)
	if err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, nil, nil
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

func NsDataMerged(ctx context.Context, client *spanner.Client, ns string,
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
		Params: map[string]any{
			"p1": ns,
		},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	var periods []TimePeriod
	var totalRows []int64
	type nsDataMergedRow struct {
		Days      int64
		DateTo    civil.Date
		TotalRows int64
	}
	rows, err := pkgspanner.ReadRows[nsDataMergedRow](iter)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range rows {
		periods = append(periods, TimePeriod{DateTo: r.DateTo, Days: int(r.Days)})
		totalRows = append(totalRows, r.TotalRows)
	}
	return periods, totalRows, nil
}

type sessionRow struct {
	Session string
}

type activeSessionRow struct {
	Session string
	Created time.Time
}

type orphanFinder struct {
	// client is the Spanner client used to execute queries.
	client *spanner.Client
	// validSessions is the set of completed session IDs present in merge_history.
	validSessions map[string]bool
	// processedSessions tracks session IDs already processed to avoid duplicates and redundant lookups.
	processedSessions map[string]bool
	// activeSessions maps registered session IDs in the sessions table to their creation time.
	activeSessions map[string]time.Time
	// cutoff is the threshold time; sessions created before this time are considered expired.
	cutoff time.Time
	// sessionCh is the channel used to send expired session IDs to deletion workers.
	sessionCh chan<- string
}

func (f *orphanFinder) stream(ctx context.Context, sql string) error {
	iter := f.client.Single().Query(ctx, spanner.Statement{SQL: sql})
	defer iter.Stop()
	for {
		r, err := pkgspanner.ReadRow[sessionRow](iter)
		if err != nil {
			return err
		}
		if r == nil {
			break
		}
		if f.validSessions[r.Session] || f.processedSessions[r.Session] {
			continue
		}
		f.processedSessions[r.Session] = true
		created, ok := f.activeSessions[r.Session]
		if !ok || created.Before(f.cutoff) {
			select {
			case f.sessionCh <- r.Session:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

// DeleteGarbage cleans up orphaned database entries that are no longer associated with active merge sessions.
//
// It identifies sessions in "files" and "functions" tables that are:
//  1. Not present in "merge_history" (i.e. they are not completed sessions).
//  2. Either missing from "sessions" table (legacy active sessions, which are deleted immediately)
//     or present in "sessions" table but created more than 1 week ago (failed/abandoned sessions).
//
// Active incomplete sessions (present in "sessions" table and created within the last week)
// are preserved to allow ongoing uploads to complete.
//
// To avoid slow anti-joins in Spanner, this function fetches all valid and active sessions first,
// then streams distinct sessions from files and functions, performing the filtering in Go.
//
// To avoid exceeding Spanner mutation limits, entries are deleted in batches of 10,000.
//
// Returns the number of deleted sessions and the total number of deleted rows.
func DeleteGarbage(ctx context.Context, client *spanner.Client) (int64, int64, error) {
	if client == nil {
		return 0, 0, fmt.Errorf("nil spannerclient")
	}

	// 1. Get all valid sessions from merge_history
	validSessions := make(map[string]bool)
	iterHistory := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT DISTINCT session FROM merge_history`})
	defer iterHistory.Stop()
	historyRows, err := pkgspanner.ReadRows[sessionRow](iterHistory)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range historyRows {
		validSessions[r.Session] = true
	}

	// 2. Get all active sessions from sessions
	activeSessions := make(map[string]time.Time)
	iterSessions := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT session, created FROM sessions`})
	defer iterSessions.Stop()
	sessionRows, err := pkgspanner.ReadRows[activeSessionRow](iterSessions)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range sessionRows {
		activeSessions[r.Session] = r.Created
	}

	// 3. Stream distinct sessions from files and functions and feed to workers.
	var deletedRows atomic.Int64
	var deletedSessions atomic.Int64
	eg, gCtx := errgroup.WithContext(ctx)

	sessionCh := make(chan string)
	const numWorkers = 10

	// Spawn workers to process garbage sessions.
	for range numWorkers {
		eg.Go(func() error {
			for session := range sessionCh {
				if err := processGarbageSession(gCtx, client, session, &deletedRows); err != nil {
					return err
				}
				deletedSessions.Add(1)
			}
			return nil
		})
	}

	finder := &orphanFinder{
		client:            client,
		validSessions:     validSessions,
		processedSessions: make(map[string]bool),
		activeSessions:    activeSessions,
		cutoff:            time.Now().Add(-oneWeekAgo),
		sessionCh:         sessionCh,
	}

	eg.Go(func() error {
		defer close(sessionCh)

		if err := finder.stream(gCtx, `SELECT DISTINCT session FROM files`); err != nil {
			return err
		}

		if err := finder.stream(gCtx, `SELECT DISTINCT session FROM functions`); err != nil {
			return err
		}
		return nil
	})

	err = eg.Wait()
	return deletedSessions.Load(), deletedRows.Load(), err
}

func processGarbageSession(ctx context.Context, client *spanner.Client, session string,
	deletedRows *atomic.Int64) error {
	if err := deleteGarbageTable(ctx, client, session, "files",
		`SELECT manager, filepath FROM files WHERE session = $1`, deletedRows); err != nil {
		return err
	}
	if err := deleteGarbageTable(ctx, client, session, "functions",
		`SELECT filepath, funcname FROM functions WHERE session = $1`, deletedRows); err != nil {
		return err
	}
	// Delete from sessions.
	mutation := spanner.Delete("sessions", spanner.Key{session})
	if _, err := client.Apply(ctx, []*spanner.Mutation{mutation}); err != nil {
		return fmt.Errorf("failed to delete session from sessions table: %w", err)
	}
	return nil
}

func deleteGarbageTable(ctx context.Context, client *spanner.Client, session, table, sql string,
	deletedRows *atomic.Int64) error {
	// Spanner limits mutations per transaction (currently 80,000).
	// We delete in batches of 10,000 rows to stay well below this limit
	// (each deleted row and its index updates count as mutations)
	// and to keep transaction overhead low.
	batchSize := 10000

	iterRows := client.Single().Query(ctx, spanner.Statement{
		SQL:    sql,
		Params: map[string]any{"p1": session},
	})
	defer iterRows.Stop()

	var batch []spanner.Key
	for {
		row, err := iterRows.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("iterRows.Next (%s): %w", table, err)
		}
		var keyPart1, keyPart2 string
		if err = row.Columns(&keyPart1, &keyPart2); err != nil {
			return fmt.Errorf("row.Columns (%s): %w", table, err)
		}

		batch = append(batch, spanner.Key{session, keyPart1, keyPart2})

		if len(batch) >= batchSize {
			if err := deleteBatch(ctx, table, batch, client, deletedRows); err != nil {
				return err
			}
			batch = nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if len(batch) > 0 {
		if err := deleteBatch(ctx, table, batch, client, deletedRows); err != nil {
			return err
		}
	}

	return nil
}

func deleteBatch(ctx context.Context, table string, batch []spanner.Key, client *spanner.Client,
	deletedRows *atomic.Int64) error {
	ks := spanner.KeySetFromKeys(batch...)
	ksSize := len(batch)
	mutation := spanner.Delete(table, ks)
	_, err := client.Apply(ctx, []*spanner.Mutation{mutation})
	if err == nil {
		deletedRows.Add(int64(ksSize))
	}
	return err
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
	FilePath  string
}

// FilesCoverageStream streams information about all the line coverage.
// It is expensive and better to be used for time insensitive operations.
func FilesCoverageStream(ctx context.Context, client *spanner.Client, scope *SelectScope,
) (<-chan *FileCoverageWithLineInfo, <-chan error) {
	iter := client.Single().Query(ctx,
		filesCoverageWithDetailsStmt(scope, true))
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
	ctx context.Context, client *spanner.Client, scope *SelectScope, onlyUnique bool,
) ([]*FileCoverageWithDetails, error) {
	var res []*FileCoverageWithDetails
	for _, timePeriod := range scope.Periods {
		needLinesDetails := onlyUnique
		iterManager := client.Single().Query(ctx,
			filesCoverageWithDetailsStmt(&SelectScope{
				Ns:        scope.Ns,
				Subsystem: scope.Subsystem,
				Manager:   scope.Manager,
				Periods:   []TimePeriod{timePeriod},
			}, needLinesDetails))
		defer iterManager.Stop()

		var err error
		var periodRes []*FileCoverageWithDetails
		if onlyUnique {
			iterAll := client.Single().Query(ctx,
				filesCoverageWithDetailsStmt(&SelectScope{
					Ns:        scope.Ns,
					Subsystem: scope.Subsystem,
					Manager:   "",
					Periods:   []TimePeriod{timePeriod},
				}, needLinesDetails))
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

func filesCoverageWithDetailsStmt(scope *SelectScope, withLines bool) spanner.Statement {
	manager := scope.Manager
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
		Params: map[string]any{
			"p1": scope.Ns,
			"p2": scope.Periods[0].DateTo,
			"p3": scope.Periods[0].Days,
			"p4": manager,
		},
	}
	if scope.Subsystem != "" {
		stmt.SQL += " and $5=ANY(subsystems)"
		stmt.Params["p5"] = scope.Subsystem
	}
	if scope.FilePath != "" {
		stmt.SQL += " and starts_with(files.filepath, $6)"
		stmt.Params["p6"] = scope.FilePath
	}
	stmt.SQL += "\norder by files.filepath"
	return stmt
}

func readCoverage(ctx context.Context, iterManager *spanner.RowIterator) ([]*FileCoverageWithDetails, error) {
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
func readCoverageUniq(full, mgr *spanner.RowIterator,
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
	ctx context.Context, iter *spanner.RowIterator, ch chan<- *K) error {
	for {
		r, err := pkgspanner.ReadRow[K](iter)
		if err != nil {
			return err
		}
		if r == nil {
			break
		}
		select {
		case ch <- r:
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

// UniqCoverage returns partial hitcounts that are the only source of the full hitcounts.
func UniqCoverage(fullCov, partCov map[int]int64) map[int]int64 {
	res := maps.Clone(partCov)
	for ln := range partCov {
		if partCov[ln] != fullCov[ln] {
			res[ln] = 0
		}
	}
	return res
}

func RegenerateSubsystems(ctx context.Context, ns string, sss []*subsystem.Subsystem,
	client *spanner.Client) (int, error) {
	ssMatcher := subsystem.MakePathMatcher(sss)
	ssCache := make(map[string][]string)
	filePaths, err := getFilePaths(ctx, ns, client)
	if err != nil {
		return 0, err
	}
	var mutations []*spanner.Mutation
	for _, filePath := range filePaths {
		subsystems := getFileSubsystems(filePath, ssMatcher, ssCache)
		mutations = append(mutations, fileSubsystemsMutation(ns, filePath, subsystems))
	}
	// There is a limit on the number of mutations per transaction (80k) imposed by the DB.
	// Expected mutations count is < 20k and looks safe to do w/o batching.
	if _, err = client.Apply(ctx, mutations); err != nil {
		return 0, err
	}
	return len(mutations), nil
}

func getFilePaths(ctx context.Context, ns string, client *spanner.Client) ([]string, error) {
	iter := client.Single().Query(ctx, spanner.Statement{
		// Take file names from 1 quarterly, 1 monthly and 1 daily aggregations.
		SQL: `
select
  distinct files.filepath
from files
where files.session in (
  select session from (
    select
        session
    from
      merge_history
    where
      namespace = $1
    order by dateto desc, duration desc
    limit 3
  ) as sub
)
order by files.filepath
`,
		Params: map[string]any{
			"p1": ns,
		},
	})
	defer iter.Stop()

	type filepathRow struct {
		Filepath string
	}
	rows, err := pkgspanner.ReadRows[filepathRow](iter)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, r := range rows {
		res = append(res, r.Filepath)
	}
	return res, nil
}
