// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package spanner

import (
	"context"
	"testing"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEntity struct {
	ID   string
	Val  int64
	Text string
}

func setupTestDB(t *testing.T) (*spanner.Client, context.Context) {
	ddl := []string{
		`CREATE TABLE TestEntities (
			ID STRING(MAX) NOT NULL,
			Val INT64 NOT NULL,
			Text STRING(MAX),
		) PRIMARY KEY (ID)`,
	}
	uri := NewTestDB(t, databasepb.DatabaseDialect_GOOGLE_STANDARD_SQL, ddl)
	ctx := context.Background()
	client, err := spanner.NewClient(ctx, uri)
	require.NoError(t, err)

	// Insert some data.
	_, err = client.Apply(ctx, []*spanner.Mutation{
		spanner.Insert("TestEntities", []string{"ID", "Val", "Text"}, []any{"1", int64(10), "one"}),
		spanner.Insert("TestEntities", []string{"ID", "Val", "Text"}, []any{"2", int64(20), "two"}),
		spanner.Insert("TestEntities", []string{"ID", "Val", "Text"}, []any{"3", int64(30), "three"}),
	})
	require.NoError(t, err)

	return client, ctx
}

func TestReadRows(t *testing.T) {
	client, ctx := setupTestDB(t)
	defer client.Close()

	iter := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT * FROM TestEntities ORDER BY ID"})
	defer iter.Stop()

	rows, err := ReadRows[testEntity](iter)
	require.NoError(t, err)
	require.Len(t, rows, 3)

	assert.Equal(t, &testEntity{ID: "1", Val: 10, Text: "one"}, rows[0])
	assert.Equal(t, &testEntity{ID: "2", Val: 20, Text: "two"}, rows[1])
	assert.Equal(t, &testEntity{ID: "3", Val: 30, Text: "three"}, rows[2])
}

func TestReadRow(t *testing.T) {
	client, ctx := setupTestDB(t)
	defer client.Close()

	t.Run("ExistingRow", func(t *testing.T) {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT * FROM TestEntities WHERE ID = '2'"})
		defer iter.Stop()

		row, err := ReadRow[testEntity](iter)
		require.NoError(t, err)
		require.NotNil(t, row)
		assert.Equal(t, &testEntity{ID: "2", Val: 20, Text: "two"}, row)
	})

	t.Run("NonexistentRow", func(t *testing.T) {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT * FROM TestEntities WHERE ID = 'nonexistent'"})
		defer iter.Stop()

		row, err := ReadRow[testEntity](iter)
		require.NoError(t, err)
		assert.Nil(t, row)
	})
}
