// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeriesPatchBodies(t *testing.T) {
	emptySeries := &Series{}
	require.Nil(t, emptySeries.PatchBodies())

	series := &Series{
		Patches: []SeriesPatch{
			{Body: []byte("patch1")},
			{Body: []byte("patch2")},
		},
	}
	require.Equal(t, [][]byte{[]byte("patch1"), []byte("patch2")}, series.PatchBodies())
}

func TestSeriesModifiedFiles(t *testing.T) {
	var nilSeries *Series
	require.Nil(t, nilSeries.ModifiedFiles())

	emptySeries := &Series{}
	require.Empty(t, emptySeries.ModifiedFiles())

	series := &Series{
		Patches: []SeriesPatch{
			{Body: []byte("diff --git a/b.c b/b.c\ndiff --git a/a.c b/a.c\n")},
			{Body: []byte("diff --git a/b.c b/b.c\ndiff --git a/c.c b/c.c\n")},
		},
	}
	require.Equal(t, []string{"a.c", "b.c", "c.c"}, series.ModifiedFiles())
}
