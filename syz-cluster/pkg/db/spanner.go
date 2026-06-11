// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"embed"
	"errors"
	"testing"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/golang-migrate/migrate/v4"
	migrate_spanner "github.com/golang-migrate/migrate/v4/database/spanner"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:embed migrations/*.sql
var migrationsFs embed.FS

func RunMigrations(uri string) error {
	m, err := getMigrateInstance(uri)
	if err != nil {
		return err
	}
	err = m.Up()
	if err == migrate.ErrNoChange {
		// Not really an error.
		return nil
	}
	return err
}

func getMigrateInstance(uri string) (*migrate.Migrate, error) {
	sourceDriver, err := iofs.New(migrationsFs, "migrations")
	if err != nil {
		return nil, err
	}
	s := &migrate_spanner.Spanner{}
	dbDriver, err := s.Open("spanner://" + uri + "?x-clean-statements=true")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "spanner", dbDriver)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewTransientDB(t *testing.T) (*spanner.Client, context.Context) {
	uri := pkgspanner.NewTestDB(t, databasepb.DatabaseDialect_GOOGLE_STANDARD_SQL, nil)
	ctx := t.Context()
	client, err := spanner.NewClient(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	err = RunMigrations(uri)
	if err != nil {
		t.Fatal(err)
	}
	return client, ctx
}

type dbQuerier interface {
	Query(context.Context, spanner.Statement) *spanner.RowIterator
}

func readRow[T any](iter *spanner.RowIterator) (*T, error) {
	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var obj T
	err = row.ToStruct(&obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

func readRows[T any](iter *spanner.RowIterator) ([]*T, error) {
	var ret []*T
	for {
		obj, err := readRow[T](iter)
		if err != nil {
			return nil, err
		}
		if obj == nil {
			break
		}
		ret = append(ret, obj)
	}
	return ret, nil
}

func readEntity[T any](ctx context.Context, txn dbQuerier, stmt spanner.Statement) (*T, error) {
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()
	return readRow[T](iter)
}

func readEntities[T any](ctx context.Context, txn dbQuerier, stmt spanner.Statement) ([]*T, error) {
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()
	return readRows[T](iter)
}

const NoLimit = 0

func addLimit(stmt *spanner.Statement, limit int) {
	if limit != NoLimit {
		stmt.SQL += " LIMIT @limit"
		stmt.Params["limit"] = limit
	}
}

type genericEntityOps[EntityType, KeyType any] struct {
	client   *spanner.Client
	keyField string
	table    string
}

func (g *genericEntityOps[EntityType, KeyType]) GetByID(ctx context.Context, key KeyType) (*EntityType, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM " + g.table + " WHERE " + g.keyField + "=@key",
		Params: map[string]any{"key": key},
	}
	return readEntity[EntityType](ctx, g.client.Single(), stmt)
}

var ErrEntityNotFound = errors.New("entity not found")

func (g *genericEntityOps[EntityType, KeyType]) Update(ctx context.Context, key KeyType,
	cb func(*EntityType) error) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			entity, err := readEntity[EntityType](ctx, txn, spanner.Statement{
				SQL:    "SELECT * from `" + g.table + "` WHERE `" + g.keyField + "`=@key",
				Params: map[string]any{"key": key},
			})
			if err != nil {
				return err
			}
			if entity == nil {
				return ErrEntityNotFound
			}
			err = cb(entity)
			if err != nil {
				return err
			}
			m, err := spanner.UpdateStruct(g.table, entity)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

var errEntityExists = errors.New("entity already exists")

func (g *genericEntityOps[EntityType, KeyType]) Insert(ctx context.Context, obj *EntityType) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			insert, err := spanner.InsertStruct(g.table, obj)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{insert})
		})
	if status.Code(err) == codes.AlreadyExists {
		return errEntityExists
	}
	return err
}

func (g *genericEntityOps[EntityType, KeyType]) Upsert(ctx context.Context, obj *EntityType) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			m, err := spanner.InsertOrUpdateStruct(g.table, obj)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

func (g *genericEntityOps[EntityType, KeyType]) readEntities(ctx context.Context, stmt spanner.Statement) (
	[]*EntityType, error) {
	return readEntities[EntityType](ctx, g.client.Single(), stmt)
}
