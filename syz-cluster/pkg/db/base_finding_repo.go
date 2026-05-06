// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
)

type BaseFindingRepository struct {
	client *spanner.Client
}

func NewBaseFindingRepository(client *spanner.Client) *BaseFindingRepository {
	return &BaseFindingRepository{
		client: client,
	}
}

func (repo *BaseFindingRepository) Save(ctx context.Context, info *BaseFinding) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			m, err := spanner.InsertOrUpdateStruct("BaseFindings", info)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

func (repo *BaseFindingRepository) Exists(ctx context.Context, info *BaseFinding) (bool, error) {
	const baseFindingSearchSpan = 7 * 24 * time.Hour

	params := map[string]any{
		"commit": info.CommitHash,
		"config": info.Config,
		"arch":   info.Arch,
		"title":  info.Title,
	}
	filters := "CommitHash = @commit"
	if !info.CommitDate.IsNull() {
		// Since we may use different base commits, looking only at the exact
		// commit hash is not enough.
		filters = "(" + filters + " OR (CommitDate >= @minDate AND CommitDate <= @maxDate))"
		params["minDate"] = info.CommitDate.Time.Add(-baseFindingSearchSpan)
		params["maxDate"] = info.CommitDate.Time
	}
	entity, err := readEntity[BaseFinding](ctx, repo.client.Single(), spanner.Statement{
		SQL: `SELECT * FROM BaseFindings WHERE
Config = @config AND
Arch = @arch AND
Title = @title AND ` + filters,
		Params: params,
	})
	return entity != nil, err
}
