// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewBuildRepository(client)

	build := &Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		CommitHash: "good",
		CommitDate: time.Now(),
		ConfigName: "kasan",
		Status:     BuildSuccess,
	}
	err := repo.Insert(ctx, build)
	require.NoError(t, err)
	require.NotEmpty(t, build.ID)

	got, err := repo.GetByID(ctx, build.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "good", got.CommitHash)
	assert.Equal(t, BuildSuccess, got.Status)
}
