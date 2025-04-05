// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
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

var ErrFindingExists = errors.New("the finding already exists")

// Save either adds the finding to the database or returns ErrFindingExists.
func (repo *FindingRepository) Save(ctx context.Context, finding *Finding) error {
	if finding.ID == "" {
		finding.ID = uuid.NewString()
	}
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if there is still no such finding.
			stmt := spanner.Statement{
				SQL: "SELECT * from `Findings` WHERE `SessionID`=@sessionID " +
					"AND `TestName` = @testName AND `Title`=@title",
				Params: map[string]interface{}{
					"sessionID": finding.SessionID,
					"testName":  finding.TestName,
					"title":     finding.Title,
				},
			}
			iter := txn.Query(ctx, stmt)
			defer iter.Stop()
			_, iterErr := iter.Next()
			if iterErr == nil {
				return ErrFindingExists
			} else if iterErr != iterator.Done {
				return iterErr
			}
			m, err := spanner.InsertStruct("Findings", finding)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

// nolint: dupl
func (repo *FindingRepository) ListForSession(ctx context.Context, sessionID string) ([]*Finding, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM `Findings` WHERE `SessionID` = @session ORDER BY `TestName`, `Title`",
		Params: map[string]interface{}{"session": sessionID},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[Finding](iter)
}
