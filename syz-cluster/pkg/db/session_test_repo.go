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

func (repo *SessionTestRepository) InsertOrUpdate(ctx context.Context, test *SessionTest) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if the test already exists.
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

func (repo *SessionTestRepository) Get(ctx context.Context, sessionID, testName string) (*SessionTest, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionTests` WHERE `SessionID` = @session AND `TestName` = @name",
		Params: map[string]interface{}{
			"session": sessionID,
			"name":    testName,
		},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[SessionTest](iter)
}

type FullSessionTest struct {
	*SessionTest
	BaseBuild    *Build
	PatchedBuild *Build
}

func (repo *SessionTestRepository) BySession(ctx context.Context, sessionID string) ([]*FullSessionTest, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionTests` WHERE `SessionID` = @session" +
			" ORDER BY `UpdatedAt`",
		Params: map[string]interface{}{"session": sessionID},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	list, err := readEntities[SessionTest](iter)
	if err != nil {
		return nil, err
	}
	var ret []*FullSessionTest
	needBuilds := map[string][]**Build{}
	for _, obj := range list {
		full := &FullSessionTest{SessionTest: obj}
		ret = append(ret, full)
		if id := obj.BaseBuildID.String(); !obj.BaseBuildID.IsNull() {
			needBuilds[id] = append(needBuilds[id], &full.BaseBuild)
		}
		if id := obj.PatchedBuildID.String(); !obj.PatchedBuildID.IsNull() {
			needBuilds[id] = append(needBuilds[id], &full.PatchedBuild)
		}
	}
	if len(needBuilds) > 0 {
		var keys []string
		for key := range needBuilds {
			keys = append(keys, key)
		}
		stmt := spanner.Statement{
			SQL:    "SELECT * FROM `Builds` WHERE `ID` IN UNNEST(@ids)",
			Params: map[string]interface{}{"ids": keys},
		}
		iter := repo.client.Single().Query(ctx, stmt)
		defer iter.Stop()
		builds, err := readEntities[Build](iter)
		if err != nil {
			return nil, err
		}
		for _, build := range builds {
			for _, patch := range needBuilds[build.ID] {
				*patch = build
			}
		}
	}
	return ret, nil
}
