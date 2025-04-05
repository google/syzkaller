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
		build.ID = uuid.NewString()
	}
	return repo.genericEntityOps.Insert(ctx, build)
}

type LastBuildParams struct {
	Arch       string
	TreeName   string
	ConfigName string
	Status     string
	Commit     string
}

func (repo *BuildRepository) LastBuiltTree(ctx context.Context, params *LastBuildParams) (*Build, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM `Builds` WHERE 1=1",
		Params: map[string]interface{}{},
	}
	if params.Arch != "" {
		stmt.SQL += " AND `Arch` = @arch"
		stmt.Params["arch"] = params.Arch
	}
	if params.TreeName != "" {
		stmt.SQL += " AND `TreeName` = @tree"
		stmt.Params["tree"] = params.TreeName
	}
	if params.ConfigName != "" {
		stmt.SQL += " AND `ConfigName` = @config"
		stmt.Params["config"] = params.ConfigName
	}
	if params.Status != "" {
		stmt.SQL += " AND `Status` = @status"
		stmt.Params["status"] = params.Status
	}
	if params.Commit != "" {
		stmt.SQL += " AND `CommitHash` = @commit"
		stmt.Params["commit"] = params.Commit
	}
	stmt.SQL += " ORDER BY `CommitDate` DESC LIMIT 1"
	iter := repo.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[Build](iter)
}
