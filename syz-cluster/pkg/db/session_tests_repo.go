// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

type SessionTestRepository struct {
	client *spanner.Client
}

func NewSessionTestRepository(client *spanner.Client) *SessionTestRepository {
	return &SessionTestRepository{
		client: client,
	}
}

func (repo *SessionTestRepository) Insert(ctx context.Context, test *SessionTest) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if the series already exists.
			stmt := spanner.Statement{
				SQL: "SELECT * from `SessionTests` WHERE `SessionID`=@sessionID AND `TestName` = @testName",
				Params: map[string]interface{}{
					"sessionID": test.SessionID,
					"testName":  test.TestName,
				},
			}
			iter := txn.Query(ctx, stmt)
			defer iter.Stop()

			var stmts []*spanner.Mutation

			_, iterErr := iter.Next()
			if iterErr == nil {
				m, err := spanner.UpdateStruct("SessionTests", test)
				if err != nil {
					return err
				}
				stmts = append(stmts, m)
			} else if iterErr != iterator.Done {
				return iterErr
			} else {
				m, err := spanner.InsertStruct("SessionTests", test)
				if err != nil {
					return err
				}
				stmts = append(stmts, m)
			}
			return txn.BufferWrite(stmts)
		})
	return err
}

func (repo *SessionTestRepository) BySession(ctx context.Context, sessionID string) ([]*SessionTest, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionTests` WHERE `SessionID` = @session" +
			" ORDER BY `TestName`",
		Params: map[string]interface{}{
			"session": sessionID,
		},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readEntities[SessionTest](iter)
}
