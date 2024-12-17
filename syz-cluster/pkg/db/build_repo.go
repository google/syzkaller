// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
)

type BuildRepository struct {
	client *spanner.Client
	*genericEntityOps[Build, string]
}

func NewBuildRepository(client *spanner.Client) *BuildRepository {
	return &BuildRepository{
		client: client,
		genericEntityOps: &genericEntityOps[Build, string]{
			client:   client,
			keyField: "ID",
			table:    "Builds",
		},
	}
}

func (repo *BuildRepository) Insert(ctx context.Context, build *Build) error {
	if build.ID == "" {
		build.ID = uuid.New().String()
	}
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			m, err := spanner.InsertStruct("Builds", build)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

func (repo *BuildRepository) LastBuiltTree(ctx context.Context, arch, tree, config string) (*Build, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `Builds` WHERE `TreeName` = @tree" +
			" AND `Arch` = @arch AND `ConfigName` = @config" +
			" AND `SeriesID` IS NULL AND `Status` = 'success'" +
			" ORDER BY `CommitDate` DESC LIMIT 1",
		Params: map[string]interface{}{
			"tree":   tree,
			"arch":   arch,
			"config": config,
		},
	}
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Build](iter)
}
