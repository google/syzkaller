// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"
	"sync"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

var ErrJobExists = errors.New("the job already exists")

type JobRepository struct {
	client *spanner.Client
	*genericEntityOps[Job, string]
}

func NewJobRepository(client *spanner.Client) *JobRepository {
	return &JobRepository{
		client: client,
		genericEntityOps: &genericEntityOps[Job, string]{
			client:   client,
			keyField: "ID",
			table:    "Jobs",
		},
	}
}

func (repo *JobRepository) Insert(ctx context.Context, job *Job,
	callback func(*Job) error) error {
	var cbErr error
	var cbOnce sync.Once
	runCallback := func() {
		if callback == nil {
			return
		}
		cbErr = callback(job)
	}

	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			// Check if the job already exists by ExtID.
			stmt := spanner.Statement{
				SQL:    "SELECT 1 FROM `Jobs` WHERE `ExtID`=@extID",
				Params: map[string]any{"extID": job.ExtID},
			}
			iter := txn.Query(ctx, stmt)
			defer iter.Stop()

			_, iterErr := iter.Next()
			if iterErr == nil {
				return ErrJobExists
			} else if iterErr != iterator.Done {
				return iterErr
			}

			cbOnce.Do(runCallback)
			if cbErr != nil {
				return cbErr
			}

			// Store the object.
			stmtInsert, err := spanner.InsertStruct("Jobs", job)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{stmtInsert})
		})
	return err
}
