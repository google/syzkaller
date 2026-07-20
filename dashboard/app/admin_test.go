// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	db "google.golang.org/appengine/v2/datastore"
)

func TestMigrateReproBools(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Create 5 unmigrated bugs with different repro levels.
	bugs := []*Bug{
		{
			Namespace:      "test1",
			Title:          "bug1",
			Status:         BugStatusOpen,
			ReproLevel:     ReproLevelNone,
			HeadReproLevel: ReproLevelNone,
		},
		{
			Namespace:      "test1",
			Title:          "bug2",
			Status:         BugStatusOpen,
			ReproLevel:     ReproLevelSyz,
			HeadReproLevel: ReproLevelSyz,
			Reporting: []BugReporting{
				{
					Name:       "reporting1",
					ReproLevel: ReproLevelSyz,
				},
			},
		},
		{
			Namespace:      "test1",
			Title:          "bug3",
			Status:         BugStatusOpen,
			ReproLevel:     ReproLevelC,
			HeadReproLevel: ReproLevelC,
			Reporting: []BugReporting{
				{
					Name:       "reporting1",
					ReproLevel: ReproLevelC,
				},
			},
		},
		{
			Namespace:      "test1",
			Title:          "bug4",
			Status:         BugStatusOpen,
			ReproLevel:     ReproLevelC,
			HeadReproLevel: ReproLevelNone,
		},
	}

	keys := make([]*db.Key, len(bugs))
	for i, bug := range bugs {
		hash := fmt.Sprintf("bug_hash_%d", i+1)
		keys[i] = db.NewKey(c.ctx, "Bug", hash, 0, nil)
		_, err := db.Put(c.ctx, keys[i], bug)
		require.NoError(t, err)
	}

	// 1. Run migration with limit = 2.
	resp, err := c.AuthGET(AccessAdmin, "/admin/migrate_repro_bools?limit=2")
	require.NoError(t, err)
	assert.Contains(t, string(resp), "Successfully migrated 2 bugs.")

	// Check that only 2 bugs were migrated so far.
	migratedCount := 0
	for _, key := range keys {
		bug := new(Bug)
		err := db.Get(c.ctx, key, bug)
		require.NoError(t, err)
		if bug.StructVersion == 1 {
			migratedCount++
		}
	}
	assert.Equal(t, 2, migratedCount)

	// 2. Run migration with limit = 2 again.
	resp, err = c.AuthGET(AccessAdmin, "/admin/migrate_repro_bools?limit=2")
	require.NoError(t, err)
	assert.Contains(t, string(resp), "Successfully migrated 2 bugs.")

	// 3. Run migration again to confirm everything is migrated.
	resp, err = c.AuthGET(AccessAdmin, "/admin/migrate_repro_bools?limit=2")
	require.NoError(t, err)
	assert.Contains(t, string(resp), "All bugs already migrated!")

	// Verify all bugs are migrated and have correct boolean values.
	expected := []struct {
		hasC    bool
		hasSyz  bool
		headC   bool
		headSyz bool
		repC    bool
		repSyz  bool
		hasRep1 bool
	}{
		{false, false, false, false, false, false, false},
		{false, true, false, true, false, true, true},
		{true, true, true, true, true, true, true},
		{true, true, false, false, false, false, false},
	}

	for i, key := range keys {
		bug := new(Bug)
		err := db.Get(c.ctx, key, bug)
		require.NoError(t, err)

		exp := expected[i]
		assert.Equal(t, 1, bug.StructVersion)
		assert.Equal(t, exp.hasC, bug.HasCRepro, "bug %d HasCRepro", i+1)
		assert.Equal(t, exp.hasSyz, bug.HasSyzRepro, "bug %d HasSyzRepro", i+1)
		assert.Equal(t, exp.headC, bug.HeadHasCRepro, "bug %d HeadHasCRepro", i+1)
		assert.Equal(t, exp.headSyz, bug.HeadHasSyzRepro, "bug %d HeadHasSyzRepro", i+1)

		if exp.hasRep1 {
			require.Len(t, bug.Reporting, 1)
			assert.Equal(t, dashapi.ReproLevelFromCAndSyz(exp.repC, exp.repSyz),
				bug.Reporting[0].ReproLevel, "bug %d Reporting ReproLevel", i+1)
		}
	}
}
