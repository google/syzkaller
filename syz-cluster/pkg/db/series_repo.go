// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

// TODO: split off some SeriesPatchesRepository.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

type SeriesRepository struct {
	client *spanner.Client
	*genericEntityOps[Series, string]
}

func NewSeriesRepository(client *spanner.Client) *SeriesRepository {
	return &SeriesRepository{
		client: client,
		genericEntityOps: &genericEntityOps[Series, string]{
			client:   client,
			keyField: "ID",
			table:    "Series",
		},
	}
}

// TODO: move to SeriesPatchesRepository?
func (repo *SeriesRepository) PatchByID(ctx context.Context, id string) (*Patch, error) {
	return readEntity[Patch](ctx, repo.client.Single(), spanner.Statement{
		SQL:    "SELECT * FROM Patches WHERE ID=@id",
		Params: map[string]any{"id": id},
	})
}

func (repo *SeriesRepository) GetByExtID(ctx context.Context, extID string) (*Series, error) {
	return readEntity[Series](ctx, repo.client.Single(), spanner.Statement{
		SQL:    "SELECT * FROM Series WHERE ExtID=@extID",
		Params: map[string]any{"extID": extID},
	})
}

var ErrSeriesExists = errors.New("the series already exists")

// Insert() checks whether there already exists a series with the same ExtID.
// Since Patch content is stored elsewhere, we do not demand it be filled out before calling Insert().
// Instead, Insert() obtains this data via a callback.
func (repo *SeriesRepository) Insert(ctx context.Context, series *Series,
	queryPatches func() ([]*Patch, error)) error {
	var patches []*Patch
	var patchesErr error
	var patchesOnce sync.Once
	doQueryPatches := func() {
		if queryPatches == nil {
			return
		}
		patches, patchesErr = queryPatches()
	}
	if series.ID == "" {
		series.ID = uuid.NewString()
	}
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if the series already exists.
			stmt := spanner.Statement{
				SQL:    "SELECT 1 from `Series` WHERE `ExtID`=@extID",
				Params: map[string]any{"ExtID": series.ExtID},
			}
			iter := txn.Query(ctx, stmt)
			defer iter.Stop()

			_, iterErr := iter.Next()
			if iterErr == nil {
				return ErrSeriesExists
			} else if iterErr != iterator.Done {
				return iterErr
			}
			// Query patches (once).
			patchesOnce.Do(doQueryPatches)
			if patchesErr != nil {
				return patchesErr
			}
			// Save the objects.
			var stmts []*spanner.Mutation
			seriesStmt, err := spanner.InsertStruct("Series", series)
			if err != nil {
				return err
			}
			stmts = append(stmts, seriesStmt)
			for _, patch := range patches {
				patch.ID = uuid.NewString()
				patch.SeriesID = series.ID
				stmt, err := spanner.InsertStruct("Patches", patch)
				if err != nil {
					return err
				}
				stmts = append(stmts, stmt)
			}
			return txn.BufferWrite(stmts)
		})
	return err
}

func (repo *SeriesRepository) Count(ctx context.Context) (int, error) {
	stmt := spanner.Statement{SQL: "SELECT COUNT(*) FROM `Series`"}
	var count int64
	err := repo.client.Single().Query(ctx, stmt).Do(func(row *spanner.Row) error {
		return row.Column(0, &count)
	})
	return int(count), err
}

type SeriesWithSession struct {
	Series   *Series
	Session  *Session
	Findings int
}

type SeriesFilter struct {
	Cc           string
	Status       SessionStatus
	WithFindings bool
	Limit        int
	Offset       int
	Name         string
}

// ListLatest() returns the list of series ordered by the decreasing PublishedAt value.
func (repo *SeriesRepository) ListLatest(ctx context.Context, filter SeriesFilter,
	maxPublishedAt time.Time) ([]*SeriesWithSession, error) {
	ro := repo.client.ReadOnlyTransaction()
	defer ro.Close()

	stmt := spanner.Statement{
		SQL:    "SELECT Series.* FROM Series",
		Params: map[string]any{},
	}
	var conds []string

	if !maxPublishedAt.IsZero() {
		conds = append(conds, "PublishedAt < @toTime")
		stmt.Params["toTime"] = maxPublishedAt
	}
	if filter.Cc != "" {
		conds = append(conds, "@cc IN UNNEST(Cc)")
		stmt.Params["cc"] = filter.Cc
	}
	if filter.Name != "" {
		conds = append(conds, `ID IN(
SELECT ID FROM SERIES 
WHERE SEARCH(Series.TitleTokens, @name)
UNION DISTINCT
SELECT SeriesID FROM Patches
WHERE SEARCH(Patches.TitleTokens, @name)
)`)
		stmt.Params["name"] = filter.Name
	}
	if filter.Status != SessionStatusAny {
		// It could have been an INNER JOIN in the main query, but let's favor the simpler code
		// in this function.
		// The optimizer should transform the query to a JOIN anyway.
		var statusCond = "EXISTS(SELECT 1 FROM Sessions WHERE"
		switch filter.Status {
		case SessionStatusWaiting:
			statusCond += " Sessions.SeriesID = Series.ID AND Sessions.StartedAt IS NULL"
		case SessionStatusInProgress:
			statusCond += " Sessions.ID = Series.LatestSessionID AND Sessions.FinishedAt IS NULL"
		case SessionStatusFinished:
			statusCond += " Sessions.ID = Series.LatestSessionID AND Sessions.FinishedAt IS NOT NULL" +
				" AND Sessions.SkipReason IS NULL"
		case SessionStatusSkipped:
			statusCond += " Sessions.ID = Series.LatestSessionID AND Sessions.SkipReason IS NOT NULL"
		default:
			return nil, fmt.Errorf("unknown status value: %q", filter.Status)
		}
		statusCond += ")"
		conds = append(conds, statusCond)
	}
	if filter.WithFindings {
		conds = append(conds, "Series.LatestSessionID IS NOT NULL AND EXISTS("+
			"SELECT 1 FROM Findings WHERE "+
			"Findings.SessionID = Series.LatestSessionID AND Findings.InvalidatedAt IS NULL)")
	}
	if len(conds) != 0 {
		stmt.SQL += " WHERE " + strings.Join(conds, " AND ")
	}
	stmt.SQL += " ORDER BY PublishedAt DESC, ID"
	if filter.Limit > 0 {
		stmt.SQL += " LIMIT @limit"
		stmt.Params["limit"] = filter.Limit
	}
	if filter.Offset > 0 {
		stmt.SQL += " OFFSET @offset"
		stmt.Params["offset"] = filter.Offset
	}
	seriesList, err := readEntities[Series](ctx, ro, stmt)
	if err != nil {
		return nil, err
	}

	// Now query Sessions.
	var ret []*SeriesWithSession
	for _, series := range seriesList {
		obj := &SeriesWithSession{Series: series}
		ret = append(ret, obj)
	}

	// And the rest of the data.
	err = repo.querySessions(ctx, ro, ret)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	err = repo.queryFindingCounts(ctx, ro, ret)
	if err != nil {
		return nil, fmt.Errorf("failed to query finding counts: %w", err)
	}
	return ret, nil
}

func (repo *SeriesRepository) ListAllVersions(ctx context.Context, title string) ([]*Series, error) {
	ro := repo.client.ReadOnlyTransaction()
	defer ro.Close()
	return readEntities[Series](ctx, ro, spanner.Statement{
		SQL: "SELECT ID, Version FROM SERIES where Title = @title ORDER BY Version",
		Params: map[string]any{
			"title": title,
		},
	})
}

func (repo *SeriesRepository) querySessions(ctx context.Context, ro *spanner.ReadOnlyTransaction,
	seriesList []*SeriesWithSession) error {
	idToSeries := map[string]*SeriesWithSession{}
	var keys []string
	for _, item := range seriesList {
		series := item.Series
		idToSeries[series.ID] = item
		if !series.LatestSessionID.IsNull() {
			keys = append(keys, series.LatestSessionID.String())
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sessions, err := readEntities[Session](ctx, ro, spanner.Statement{
		SQL: "SELECT * FROM Sessions WHERE ID IN UNNEST(@ids)",
		Params: map[string]any{
			"ids": keys,
		},
	})
	if err != nil {
		return err
	}
	for _, session := range sessions {
		obj := idToSeries[session.SeriesID]
		if obj != nil {
			obj.Session = session
		}
	}
	return nil
}

func (repo *SeriesRepository) queryFindingCounts(ctx context.Context, ro *spanner.ReadOnlyTransaction,
	seriesList []*SeriesWithSession) error {
	var keys []string
	sessionToSeries := map[string]*SeriesWithSession{}
	for _, series := range seriesList {
		if series.Session == nil || series.Session.Status() != SessionStatusFinished {
			continue
		}
		keys = append(keys, series.Session.ID)
		sessionToSeries[series.Session.ID] = series
	}
	if len(keys) == 0 {
		return nil
	}

	type findingCount struct {
		SessionID string `spanner:"SessionID"`
		Count     int64  `spanner:"Count"`
	}
	list, err := readEntities[findingCount](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT `SessionID`, COUNT(`ID`) as `Count` FROM `Findings` " +
			"WHERE `SessionID` IN UNNEST(@ids) AND `Findings`.`InvalidatedAt` IS NULL " +
			"GROUP BY `SessionID`",
		Params: map[string]any{
			"ids": keys,
		},
	})
	if err != nil {
		return err
	}
	for _, item := range list {
		sessionToSeries[item.SessionID].Findings = int(item.Count)
	}
	return nil
}

// golint sees too much similarity with SessionRepository's ListForSeries, but in reality there's not.
func (repo *SeriesRepository) ListPatches(ctx context.Context, series *Series) ([]*Patch, error) {
	return readEntities[Patch](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT * FROM `Patches` WHERE `SeriesID` = @seriesID ORDER BY `Seq`",
		Params: map[string]any{
			"seriesID": series.ID,
		},
	})
}
