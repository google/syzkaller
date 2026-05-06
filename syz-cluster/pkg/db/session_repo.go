// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"
	"time"

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

var ErrSessionAlreadyStarted = errors.New("the session already started")

func (repo *SessionRepository) Start(ctx context.Context, sessionID string) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			session, err := readEntity[Session](ctx, txn, spanner.Statement{
				SQL:    "SELECT * from `Sessions` WHERE `ID`=@id",
				Params: map[string]any{"id": sessionID},
			})
			if err != nil {
				return err
			}
			if !session.StartedAt.IsNull() {
				return ErrSessionAlreadyStarted
			}
			session.SetStartedAt(time.Now())
			updateSession, err := spanner.UpdateStruct("Sessions", session)
			if err != nil {
				return err
			}
			if session.JobID.IsNull() {
				series, err := readEntity[Series](ctx, txn, spanner.Statement{
					SQL:    "SELECT * from `Series` WHERE `ID`=@id",
					Params: map[string]any{"id": session.SeriesID},
				})
				if err != nil {
					return err
				}
				series.SetLatestSession(session)
				updateSeries, err := spanner.UpdateStruct("Series", series)
				if err != nil {
					return err
				}
				return txn.BufferWrite([]*spanner.Mutation{updateSeries, updateSession})
			}
			return txn.BufferWrite([]*spanner.Mutation{updateSession})
		})
	return err
}

func (repo *SessionRepository) Insert(ctx context.Context, session *Session) error {
	if session.ID == "" {
		session.ID = uuid.NewString()
	}
	return repo.genericEntityOps.Insert(ctx, session)
}

func (repo *SessionRepository) ListRunning(ctx context.Context) ([]*Session, error) {
	return repo.readEntities(ctx, spanner.Statement{
		SQL: "SELECT * FROM `Sessions` WHERE `StartedAt` IS NOT NULL AND `FinishedAt` IS NULL",
	})
}

func (repo *SessionRepository) ListWaiting(ctx context.Context, limit int) ([]*Session, error) {
	// We give priority to the job-related sessions to improve user experience.
	// Otherwise, follow the FIFO order.
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `Sessions` WHERE `StartedAt` IS NULL " +
			"ORDER BY CASE WHEN `JobID` IS NOT NULL THEN 0 ELSE 1 END, `CreatedAt`",

		Params: map[string]any{},
	}
	addLimit(&stmt, limit)
	return repo.readEntities(ctx, stmt)
}

// golint sees too much similarity with SeriesRepository's ListPatches, but in reality there's not.
func (repo *SessionRepository) ListForSeries(ctx context.Context, series *Series) ([]*Session, error) {
	return repo.readEntities(ctx, spanner.Statement{
		SQL:    "SELECT * FROM `Sessions` WHERE `SeriesID` = @series ORDER BY CreatedAt DESC",
		Params: map[string]any{"series": series.ID},
	})
}

// MissingReportList lists the session objects that are missing any SessionReport objects,
// but do have Findings.
// Once the conditions for creating a SessionRepor object become more complex, it will
// likely be not enough to have this simple method, but for now it should be fine.
func (repo *SessionRepository) MissingReportList(ctx context.Context, from time.Time, limit int) ([]*Session, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM Sessions WHERE FinishedAt IS NOT NULL " +
			" AND NOT EXISTS (" +
			"SELECT 1 FROM SessionReports WHERE SessionReports.SessionID = Sessions.ID" +
			") AND (JobID IS NOT NULL OR EXISTS (" +
			"SELECT 1 FROM Findings WHERE Findings.SessionID = Sessions.ID))",
		Params: map[string]any{},
	}
	if !from.IsZero() {
		stmt.SQL += " AND `FinishedAt` > @from"
		stmt.Params["from"] = from
	}
	stmt.SQL += " ORDER BY `FinishedAt`"
	addLimit(&stmt, limit)
	return repo.readEntities(ctx, stmt)
}
