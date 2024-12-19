// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestGetSeries(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	repo := db.NewSeriesRepository(env.Spanner)

	series := addTestSeries(t, repo, env.BlobStorage)
	service := &SeriesService{seriesRepo: repo, blobStorage: env.BlobStorage}
	ret, err := service.GetSeries(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, testSeriesReply, ret)
}

var testSeriesReply = &api.Series{
	PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
	Cc:          []string{"email"},
	Patches: [][]byte{
		[]byte("first content"),
		[]byte("second content"),
	},
}

func addTestSeries(t *testing.T, repo *db.SeriesRepository, storage blob.Storage) *db.Series {
	series := &db.Series{
		ExtID:       "ext-id",
		AuthorName:  "Name1 Name2",
		AuthorEmail: "some@email.com",
		Title:       "test series name",
		Version:     2,
		PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		Cc:          []string{"email"},
	}

	uri1, _ := storage.Store(bytes.NewReader([]byte("first content")))
	uri2, _ := storage.Store(bytes.NewReader([]byte("second content")))

	patches := []*db.Patch{
		&db.Patch{Seq: 1, Link: "first link", BodyURI: uri1},
		&db.Patch{Seq: 2, Link: "second link", BodyURI: uri2},
	}
	err := repo.Insert(context.Background(), series, func() ([]*db.Patch, error) {
		return patches, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return series
}
