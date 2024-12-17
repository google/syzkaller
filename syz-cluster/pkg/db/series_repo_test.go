// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSeriesRepositoryGet(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesRepository(client)
	series := &Series{
		ExtID:       "ext-id",
		AuthorName:  "Name1 Name2",
		AuthorEmail: "some@email.com",
		Title:       "something",
		Version:     2,
		PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		Cc:          []string{"email"},
	}
	patches := []*Patch{
		&Patch{
			Title:   "first patch",
			Seq:     1,
			Link:    "first link",
			BodyURI: "gcs://patch1",
		},
		&Patch{
			Title:   "second patch",
			Seq:     2,
			Link:    "second link",
			BodyURI: "gcs://patch2",
		},
	}
	err := repo.Insert(ctx, series, func() ([]*Patch, error) {
		return patches, nil
	})
	assert.NoError(t, err)
	// Check that we obtain the exact object from the DB.
	series2, err := repo.SeriesByID(ctx, series.ID)
	assert.NoError(t, err)
	assert.EqualValues(t, series, series2)
	// Compare the patches.
	patches2, err := repo.ListPatches(ctx, series)
	assert.NoError(t, err)
	assert.EqualValues(t, patches, patches2)
}

func TestSeriesRepositoryList(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesRepository(client)
	for _, series := range []*Series{
		&Series{
			ExtID:       "series-3",
			Title:       "Series 3",
			PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		},
		&Series{
			ExtID:       "series-1",
			Title:       "Series 1",
			PublishedAt: time.Date(2020, time.January, 1, 1, 0, 0, 0, time.UTC),
		},
		&Series{
			ExtID:       "series-2",
			Title:       "Series 2",
			PublishedAt: time.Date(2020, time.January, 1, 2, 0, 0, 0, time.UTC),
		},
	} {
		err := repo.Insert(ctx, series, func() ([]*Patch, error) { return nil, nil })
		assert.NoError(t, err)
	}

	t.Run("count", func(t *testing.T) {
		count, err := repo.Count(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	t.Run("all", func(t *testing.T) {
		list, err := repo.ListLatest(ctx, time.Time{}, 0)
		assert.NoError(t, err)
		assert.Len(t, list, 3)
	})

	t.Run("with_limit", func(t *testing.T) {
		list, err := repo.ListLatest(ctx, time.Time{}, 2)
		assert.NoError(t, err)
		assert.Len(t, list, 2)
		assert.Equal(t, "Series 3", list[0].Series.Title)
		assert.Equal(t, "Series 2", list[1].Series.Title)
	})

	t.Run("with_from", func(t *testing.T) {
		// Skips the latest series.
		list, err := repo.ListLatest(ctx, time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC), 0)
		assert.NoError(t, err)
		assert.Len(t, list, 2)
		assert.Equal(t, "Series 2", list[0].Series.Title)
		assert.Equal(t, "Series 1", list[1].Series.Title)
	})
}

func TestSeriesRepositoryUpdate(t *testing.T) {
	client, ctx := NewTransientDB(t)
	repo := NewSeriesRepository(client)
	series := &Series{
		ExtID:       "ext-id",
		AuthorName:  "Name1 Name2",
		AuthorEmail: "some@email.com",
		Title:       "something",
		Version:     2,
		PublishedAt: time.Date(2020, time.January, 1, 3, 0, 0, 0, time.UTC),
		Cc:          []string{"email"},
	}
	err := repo.Insert(ctx, series, func() ([]*Patch, error) {
		return nil, nil
	})
	assert.NoError(t, err)
	// Update the object.
	err = repo.Update(ctx, series.ID, func(series *Series) error {
		series.Title = "updated title"
		return nil
	})
	// Check that the entity has been updated.
	series2, err := repo.SeriesByID(ctx, series.ID)
	assert.NoError(t, err)
	assert.Equal(t, "updated title", series2.Title)
}
