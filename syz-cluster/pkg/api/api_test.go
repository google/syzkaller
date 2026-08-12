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

func TestIsStableBackport(t *testing.T) {
	var nilSeries *Series
	require.False(t, nilSeries.IsStableBackport())

	// Regular upstream series.
	require.False(t, (&Series{
		Title:       "net: fix some issue",
		SubjectTags: []string{"PATCH", "net-next"},
	}).IsStableBackport())

	// Stable RC review series should not be considered developer backports.
	require.False(t, (&Series{
		Title:             "5.15.138-rc1 review",
		SubjectTags:       []string{"5.15"},
		XStable:           "review",
		XKernelTestBranch: "linux-5.15.y",
	}).IsStableBackport())

	// Developer stable backports via subject tags.
	require.True(t, (&Series{
		Title:       "net: fix some issue",
		SubjectTags: []string{"PATCH", "5.15"},
	}).IsStableBackport())
	require.True(t, (&Series{
		Title:       "net: fix some issue",
		SubjectTags: []string{"linux-6.1.y"},
	}).IsStableBackport())

	// Developer stable backports via title.
	require.True(t, (&Series{
		Title: "[5.15.y] net: fix some issue",
	}).IsStableBackport())
	require.True(t, (&Series{
		Title: "v5.15: net: fix some issue",
	}).IsStableBackport())
}
