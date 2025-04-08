// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

// TODO: split off some SeriesPatchesRepository.

import (
	"context"
	"errors"
	"fmt"
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
// nolint:dupl
func (repo *SeriesRepository) PatchByID(ctx context.Context, id string) (*Patch, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Patches WHERE ID=@id",
		Params: map[string]interface{}{"id": id},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Patch](iter)
}

// nolint:dupl
func (repo *SeriesRepository) GetByExtID(ctx context.Context, extID string) (*Series, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Series WHERE ExtID=@extID",
		Params: map[string]interface{}{"extID": extID},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Series](iter)
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
				Params: map[string]interface{}{"ExtID": series.ExtID},
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
	Series  *Series
	Session *Session
}

type SeriesFilter struct {
	Cc     string
	Status SessionStatus
	Limit  int
	Offset int
}

// ListLatest() returns the list of series ordered by the decreasing PublishedAt value.
func (repo *SeriesRepository) ListLatest(ctx context.Context, filter SeriesFilter,
	maxPublishedAt time.Time) ([]*SeriesWithSession, error) {
	ro := repo.client.ReadOnlyTransaction()
	defer ro.Close()

	stmt := spanner.Statement{
		SQL:    "SELECT Series.* FROM Series WHERE 1=1",
		Params: map[string]interface{}{},
	}
	if !maxPublishedAt.IsZero() {
		stmt.SQL += " AND PublishedAt < @toTime"
		stmt.Params["toTime"] = maxPublishedAt
	}
	if filter.Cc != "" {
		stmt.SQL += " AND @cc IN UNNEST(Cc)"
		stmt.Params["cc"] = filter.Cc
	}
	if filter.Status != SessionStatusAny {
		// It could have been an INNER JOIN in the main query, but let's favor the simpler code
		// in this function.
		// The optimizer should transform the query to a JOIN anyway.
		stmt.SQL += " AND EXISTS(SELECT 1 FROM Sessions WHERE"
		switch filter.Status {
		case SessionStatusWaiting:
			stmt.SQL += " Sessions.SeriesID = Series.ID AND Sessions.StartedAt IS NULL"
		case SessionStatusInProgress:
			stmt.SQL += " Sessions.ID = Series.LatestSessionID AND Sessions.FinishedAt IS NULL"
		case SessionStatusFinished:
			stmt.SQL += " Sessions.ID = Series.LatestSessionID AND Sessions.FinishedAt IS NOT NULL"
		default:
			return nil, fmt.Errorf("unknown status value: %q", filter.Status)
		}
		stmt.SQL += ")"
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
	iter := ro.Query(ctx, stmt)
	defer iter.Stop()

	seriesList, err := readEntities[Series](iter)
	if err != nil {
		return nil, err
	}

	// Now query Sessions.
	var keys []string
	var ret []*SeriesWithSession
	idToSeries := map[string]*SeriesWithSession{}
	for _, series := range seriesList {
		if !series.LatestSessionID.IsNull() {
			keys = append(keys, series.LatestSessionID.String())
		}
		obj := &SeriesWithSession{Series: series}
		ret = append(ret, obj)
		idToSeries[series.ID] = obj
	}
	if len(keys) > 0 {
		iter := ro.Query(ctx, spanner.Statement{
			SQL: "SELECT * FROM Sessions WHERE ID IN UNNEST(@ids)",
			Params: map[string]interface{}{
				"ids": keys,
			},
		})
		defer iter.Stop()
		sessions, err := readEntities[Session](iter)
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			obj := idToSeries[session.SeriesID]
			if obj != nil {
				obj.Session = session
			}
		}
	}
	return ret, nil
}

// golint sees too much similarity with SessionRepository's ListForSeries, but in reality there's not.
// nolint:dupl
func (repo *SeriesRepository) ListPatches(ctx context.Context, series *Series) ([]*Patch, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `Patches` WHERE `SeriesID` = @seriesID ORDER BY `Seq`",
		Params: map[string]interface{}{
			"seriesID": series.ID,
		},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Patch](iter)
}
