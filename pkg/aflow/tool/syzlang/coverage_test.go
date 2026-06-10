// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"os"
	"path/filepath"
	"strings"
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

	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)
	res, err := getCoverageFiles(ctx, reproduceState{TargetOS: "linux", TargetArch: "amd64"}, CoverageFilesArgs{
		ExecutionCachedID: reproExecCachedID,
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

	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc-2", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)

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
		ExecutionCachedID: reproExecCachedID,
		Filename:          "foo.c",
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

	// Test truncation limit using the formatter directly.
	lines := []int{5, 6, 7}
	srcLines := strings.Split(srcContent, "\n")
	formatter := newCoverageFormatter(srcLines, 5)
	truncated := formatter.addFunction("foo", lines)

	require.True(t, truncated)
	require.Len(t, formatter.snippets, 1)
	require.Equal(t, 0, formatter.remainingLines)

	expectedSnippetTrunc := `Function: foo
     1: 1
     2: 2
     3: 3
     4: 4
*    5: void foo(void) {
[Truncated due to reaching maximum line limit. Use 'Functions' to narrow your query]
`
	require.Equal(t, expectedSnippetTrunc, formatter.snippets[0])
}

func TestFileCoverageNoCoverage(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Provide empty coverage for this test.
	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc-3", func() (map[string]any, error) {
		return map[string]any{"Coverage": [][]symbolizer.Frame{}}, nil
	})
	require.NoError(t, err)

	_, err = getFileCoverage(ctx, reproduceState{}, FileCoverageArgs{
		ExecutionCachedID: reproExecCachedID,
		Filename:          "nonexistent.c",
	})
	require.IsType(t, aflow.BadCallError(""), err)
}

func TestFileCoverageMissingFunction(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{File: "foo.c", Func: "foo", Line: 5},
		},
	}

	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc-4", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)

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
		ExecutionCachedID: reproExecCachedID,
		Filename:          "foo.c",
		Functions:         []string{"foo", "nonexistent_function"},
	})
	require.NoError(t, err)

	require.Len(t, res.Snippets, 2)
	require.Contains(t, res.Snippets[1], "nonexistent_function: [No coverage found or function does not exist]")
}
