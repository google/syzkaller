// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
)

type BuildRepository struct {
	*genericEntityOps[Build, string]
}

func NewBuildRepository(client *spanner.Client) *BuildRepository {
	return &BuildRepository{
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
