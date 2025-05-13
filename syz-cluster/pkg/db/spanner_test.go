// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrations(t *testing.T) {
	// Run, rollback and then again apply all DB migrations.
	client, _ := NewTransientDB(t)
	m, err := getMigrateInstance(client.DatabaseName())
	require.NoError(t, err)
	err = m.Down()
	require.NoError(t, err, "migrating down failed")
	err = m.Up()
	require.NoError(t, err, "migrating up again failed")
}
