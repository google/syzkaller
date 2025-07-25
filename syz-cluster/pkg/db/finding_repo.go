// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
)

type FindingRepository struct {
	client *spanner.Client
	*genericEntityOps[Finding, string]
}

func NewFindingRepository(client *spanner.Client) *FindingRepository {
	return &FindingRepository{
		client: client,
		genericEntityOps: &genericEntityOps[Finding, string]{
			client:   client,
			keyField: "ID",
			table:    "Findings",
		},
	}
}

type FindingID struct {
	SessionID string
	TestName  string
	Title     string
}

// Store queries the information about the session and the existing finding and then
// requests a new Finding object to replace the old one.
// If the callback returns nil, nothing it updated.
func (repo *FindingRepository) Store(ctx context.Context, id *FindingID,
	cb func(session *Session, old *Finding) (*Finding, error)) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Query the existing finding, if it exists.
			stmt := spanner.Statement{
				SQL: "SELECT * from `Findings` WHERE `SessionID`=@sessionID " +
					"AND `TestName` = @testName AND `Title`=@title",
				Params: map[string]interface{}{
					"sessionID": id.SessionID,
					"testName":  id.TestName,
					"title":     id.Title,
				},
			}
			iter := txn.Query(ctx, stmt)
			oldFinding, err := readOne[Finding](iter)
			iter.Stop()
			if err != nil {
				return err
			}
			// Query the Session object.
			stmt = spanner.Statement{
				SQL:    "SELECT * FROM `Sessions` WHERE `ID`=@id",
				Params: map[string]interface{}{"id": id.SessionID},
			}
			iter = txn.Query(ctx, stmt)
			session, err := readOne[Session](iter)
			iter.Stop()
			if err != nil {
				return err
			}
			// Query the callback.
			finding, err := cb(session, oldFinding)
			if err != nil {
				return err
			} else if finding == nil {
				return nil // Just abort.
			} else if finding.ID == "" {
				finding.ID = uuid.NewString()
			}
			// Insert the finding.
			m, err := spanner.InsertStruct("Findings", finding)
			if err != nil {
				return err
			}
			var mutations []*spanner.Mutation
			if oldFinding != nil {
				mutations = append(mutations, spanner.Delete("Findings", spanner.Key{oldFinding.ID}))
			}
			mutations = append(mutations, m)
			return txn.BufferWrite(mutations)
		})
	return err
}

var errFindingExists = errors.New("the finding already exists")

// A helper for tests.
func (repo *FindingRepository) mustStore(ctx context.Context, finding *Finding) error {
	return repo.Store(ctx, &FindingID{
		SessionID: finding.SessionID,
		TestName:  finding.TestName,
		Title:     finding.Title,
	}, func(_ *Session, old *Finding) (*Finding, error) {
		if old != nil {
			return nil, errFindingExists
		}
		return finding, nil
	})
}

// nolint: dupl
func (repo *FindingRepository) ListForSession(ctx context.Context, sessionID string, limit int) ([]*Finding, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM `Findings` WHERE `SessionID` = @session ORDER BY `TestName`, `Title`",
		Params: map[string]interface{}{"session": sessionID},
	}
	addLimit(&stmt, limit)
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Finding](iter)
}
