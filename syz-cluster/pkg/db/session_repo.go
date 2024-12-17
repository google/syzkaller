// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
)

type SessionRepository struct {
	client *spanner.Client
	*genericEntityOps[Session, string]
}

func NewSessionRepository(client *spanner.Client) *SessionRepository {
	return &SessionRepository{
		client: client,
		genericEntityOps: &genericEntityOps[Session, string]{
			client:   client,
			keyField: "ID",
			table:    "Sessions",
		},
	}
}

func (repo *SessionRepository) Insert(ctx context.Context, series *Series, session *Session) error {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// TODO: we need to update LastSessionID only for sessions whose results might
			// be reported to the author.
			stmt := spanner.Statement{
				SQL:    "SELECT * from `Series` WHERE `ID`=@id",
				Params: map[string]interface{}{"id": series.ID},
			}
			iter := txn.Query(ctx, stmt)
			series, err := readOne[Series](iter)
			iter.Stop()
			if err != nil {
				return err
			}
			series.SetLatestSession(session)
			updateSeries, err := spanner.UpdateStruct("Series", series)
			if err != nil {
				return err
			}
			session.SeriesID = series.ID
			insertSession, err := spanner.InsertStruct("Sessions", session)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{updateSeries, insertSession})
		})
	return err
}

func (repo *SessionRepository) ListRunning(ctx context.Context) ([]*Session, error) {
	stmt := spanner.Statement{SQL: "SELECT * FROM `Sessions` WHERE `FinishedAt` IS NULL"}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Session](iter)
}

// golint sees too much similarity with SeriesRepository's ListPatches, but in reality there's not.
// nolint:dupl
func (repo *SessionRepository) ListForSeries(ctx context.Context, series *Series) ([]*Session, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM `Sessions` WHERE `SeriesID` = @series ORDER BY CreatedAt DESC",
		Params: map[string]interface{}{"series": series.ID},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Session](iter)
}
