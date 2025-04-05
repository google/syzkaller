// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLastSuccessfulBuild(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewBuildRepository(client)

	params := &LastBuildParams{
		Arch:       "amd64",
		TreeName:   "mainline",
		ConfigName: "kasan",
		Status:     BuildSuccess,
	}
	build, err := repo.LastBuiltTree(ctx, params)
	assert.NoError(t, err)
	assert.Nil(t, build)

	// Insert a non-successful.
	err = repo.Insert(ctx, &Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		CommitHash: "bad",
		CommitDate: time.Now(),
		ConfigName: "kasan",
		Status:     BuildFailed,
	})
	assert.NoError(t, err)

	// It should not be queried.
	build, err = repo.LastBuiltTree(ctx, params)
	assert.NoError(t, err)
	assert.Nil(t, build)

	// .. but if don't specify the status, it should be there.
	build, err = repo.LastBuiltTree(ctx, &LastBuildParams{
		TreeName: "mainline",
	})
	assert.NoError(t, err)
	assert.NotNil(t, build)

	// Insert the correct one.
	err = repo.Insert(ctx, &Build{
		Arch:       "amd64",
		TreeName:   "mainline",
		CommitHash: "good",
		CommitDate: time.Now(),
		ConfigName: "kasan",
		Status:     BuildSuccess,
	})
	assert.NoError(t, err)

	// It should be in the output.
	build, err = repo.LastBuiltTree(ctx, params)
	assert.NoError(t, err)
	assert.Equal(t, "good", build.CommitHash)

	// But not for different arguments.
	build, err = repo.LastBuiltTree(ctx, &LastBuildParams{
		Arch:       "arm64",
		TreeName:   "mainline",
		ConfigName: "kasan",
	})
	assert.NoError(t, err)
	assert.Nil(t, build)
}
