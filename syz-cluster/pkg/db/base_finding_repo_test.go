// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseFindingRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewBaseFindingRepository(client)

	// It works fine on unknown titles.
	exists, err := repo.Exists(ctx, &BaseFinding{
		CommitHash: "abcd",
		Config:     "cfg",
		Arch:       "x86",
	})
	require.NoError(t, err)
	assert.False(t, exists)

	// Add some new title.
	finding := &BaseFinding{
		CommitHash: "hash",
		Config:     "config",
		Arch:       "arch",
		Title:      "title",
	}
	err = repo.Save(ctx, finding)
	require.NoError(t, err)

	// Verify it exists.
	exists, err = repo.Exists(ctx, finding)
	require.NoError(t, err)
	assert.True(t, exists)

	// Verify date-based lookup.
	now := time.Now()
	finding.CommitHash = "hash2"
	finding.CommitDate = spanner.NullTime{Time: now, Valid: true}
	err = repo.Save(ctx, finding)
	require.NoError(t, err)

	// Same title, different commit, but close date (in the past).
	exists, err = repo.Exists(ctx, &BaseFinding{
		CommitHash: "other",
		Config:     "config",
		Arch:       "arch",
		Title:      "title",
		CommitDate: spanner.NullTime{Time: now.Add(2 * 24 * time.Hour), Valid: true},
	})
	require.NoError(t, err)
	assert.True(t, exists)

	// Same title, different commit, future date (should not match).
	exists, err = repo.Exists(ctx, &BaseFinding{
		CommitHash: "other",
		Config:     "config",
		Arch:       "arch",
		Title:      "title",
		CommitDate: spanner.NullTime{Time: now.Add(-2 * 24 * time.Hour), Valid: true},
	})
	require.NoError(t, err)
	assert.False(t, exists)

	// Same title, different commit, far past date.
	exists, err = repo.Exists(ctx, &BaseFinding{
		CommitHash: "other",
		Config:     "config",
		Arch:       "arch",
		Title:      "title",
		CommitDate: spanner.NullTime{Time: now.Add(8 * 24 * time.Hour), Valid: true},
	})
	require.NoError(t, err)
	assert.False(t, exists)
}
