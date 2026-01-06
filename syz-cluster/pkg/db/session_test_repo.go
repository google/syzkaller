// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
)

type SessionTestRepository struct {
	client *spanner.Client
}

func NewSessionTestRepository(client *spanner.Client) *SessionTestRepository {
	return &SessionTestRepository{
		client: client,
	}
}

// If the beforeSave callback is specified, it will be called before saving the entity.
func (repo *SessionTestRepository) InsertOrUpdate(ctx context.Context, test *SessionTest,
	beforeSave func(*SessionTest)) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if the test already exists.
			dbTest, err := readEntity[SessionTest](ctx, txn, spanner.Statement{
				SQL: "SELECT * from `SessionTests` WHERE `SessionID`=@sessionID AND `TestName` = @testName",
				Params: map[string]any{
					"sessionID": test.SessionID,
					"testName":  test.TestName,
				},
			})
			var stmts []*spanner.Mutation
			if err != nil {
				return err
			} else if dbTest != nil {
				if beforeSave != nil {
					beforeSave(test)
				}
				m, err := spanner.UpdateStruct("SessionTests", test)
				if err != nil {
					return err
				}
				stmts = append(stmts, m)
			} else {
				if beforeSave != nil {
					beforeSave(test)
				}
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
	return readEntity[SessionTest](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT * FROM `SessionTests` WHERE `SessionID` = @session AND `TestName` = @name",
		Params: map[string]any{
			"session": sessionID,
			"name":    testName,
		},
	})
}

type FullSessionTest struct {
	*SessionTest
	BaseBuild    *Build
	PatchedBuild *Build
}

func (repo *SessionTestRepository) BySession(ctx context.Context, sessionID string) ([]*FullSessionTest, error) {
	list, err := repo.BySessionRaw(ctx, sessionID)
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
		builds, err := readEntities[Build](ctx, repo.client.Single(), spanner.Statement{
			SQL:    "SELECT * FROM `Builds` WHERE `ID` IN UNNEST(@ids)",
			Params: map[string]any{"ids": keys},
		})
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

func (repo *SessionTestRepository) BySessionRaw(ctx context.Context, sessionID string) ([]*SessionTest, error) {
	return readEntities[SessionTest](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT * FROM `SessionTests` WHERE `SessionID` = @session" +
			" ORDER BY `UpdatedAt`",
		Params: map[string]any{"session": sessionID},
	})
}
