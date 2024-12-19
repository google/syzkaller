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

func (repo *SeriesRepository) SeriesByID(ctx context.Context, id string) (*Series, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Series WHERE ID=@id",
		Params: map[string]interface{}{"id": id},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Series](iter)
}

// TODO: move to SeriesPatchesRepository?
func (repo *SeriesRepository) PatchByID(ctx context.Context, id string) (*Patch, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Patches WHERE ID=@id",
		Params: map[string]interface{}{"id": id},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Patch](iter)
}

var SeriesExists = errors.New("the series already exists")

// Insert() checks whether there already exists a series with the same ExtID.
// Since Patch content is stored elsewhere, we do not demand it be filled out before calling Insert().
// Instead, Insert() obtains this data via a callback.
func (repo *SeriesRepository) Insert(ctx context.Context, series *Series,
	queryPatches func() ([]*Patch, error)) error {
	series.ID = uuid.New().String()
	var patches []*Patch
	var patchesErr error
	var patchesOnce sync.Once
	doQueryPatches := func() {
		if queryPatches == nil {
			return
		}
		patches, patchesErr = queryPatches()
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
				return SeriesExists
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
				patch.ID = uuid.New().String()
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
	stmt := spanner.Statement{SQL: fmt.Sprintf("SELECT COUNT(*) FROM `Series`")}
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

// ListLatest() returns the list of series ordered by the decreasing PublishedAt value.
func (repo *SeriesRepository) ListLatest(ctx context.Context,
	maxPublishedAt time.Time, limit int) ([]*SeriesWithSession, error) {

	ro := repo.client.ReadOnlyTransaction()
	defer ro.Close()

	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Series",
		Params: map[string]interface{}{},
	}
	if !maxPublishedAt.IsZero() {
		stmt.SQL += " WHERE PublishedAt < @toTime"
		stmt.Params["toTime"] = maxPublishedAt
	}
	stmt.SQL += " ORDER BY PublishedAt DESC"
	if limit > 0 {
		stmt.SQL += " LIMIT @limit"
		stmt.Params["limit"] = limit
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

func (repo *SeriesRepository) ListWithoutSession(ctx context.Context, limit int) ([]*Series, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM Series WHERE `LatestSessionID` IS NULL ORDER BY `PublishedAt`",
		Params: map[string]interface{}{},
	}
	if limit > 0 {
		stmt.SQL += " LIMIT @limit"
		stmt.Params["limit"] = limit
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Series](iter)
}

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
