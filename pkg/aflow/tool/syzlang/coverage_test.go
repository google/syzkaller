// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/stretchr/testify/require"
)

func TestCoverageFiles(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{File: "kernel/foo.c", Func: "foo", Line: 10},
			{File: "kernel/bar.c", Func: "bar", Line: 20},
		},
		{
			{File: "kernel/foo.c", Func: "foo2", Line: 30},
		},
	}

	covDir, err := ctx.Cache("coverage", "dummy-desc", func(dir string) error {
		return osutil.WriteJSON(filepath.Join(dir, "coverage.json"), dummyCov)
	})
	require.NoError(t, err)
	covID := filepath.Base(covDir)

	res, err := getCoverageFiles(ctx, reproduceState{}, CoverageFilesArgs{
		CoverageID: covID,
	})
	require.NoError(t, err)

	require.Equal(t, []string{"kernel/bar.c", "kernel/foo.c"}, res.Files)
}

func TestFileCoverage(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{File: "foo.c", Func: "foo", Line: 5},
			{File: "foo.c", Func: "foo", Line: 6},
			{File: "foo.c", Func: "foo", Line: 7},
		},
	}

	covDir, err := ctx.Cache("coverage", "dummy-desc-2", func(dir string) error {
		return osutil.WriteJSON(filepath.Join(dir, "coverage.json"), dummyCov)
	})
	require.NoError(t, err)
	covID := filepath.Base(covDir)

	kernelSrc := t.TempDir()
	err = osutil.MkdirAll(kernelSrc)
	require.NoError(t, err)

	srcContent := `1
2
3
4
void foo(void) {
    int a = 1;
    a++;
}
`
	err = os.WriteFile(filepath.Join(kernelSrc, "foo.c"), []byte(srcContent), 0644)
	require.NoError(t, err)

	res, err := getFileCoverage(ctx, reproduceState{KernelSrc: kernelSrc}, FileCoverageArgs{
		CoverageID: covID,
		Filename:   "foo.c",
	})
	require.NoError(t, err)

	require.Len(t, res.Snippets, 1)

	expectedSnippet := `Function: foo
     1: 1
     2: 2
     3: 3
     4: 4
*    5: void foo(void) {
*    6:     int a = 1;
*    7:     a++;
     8: }
     9: 
`
	require.Equal(t, expectedSnippet, res.Snippets[0])
}
