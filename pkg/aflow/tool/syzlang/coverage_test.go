// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
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

func TestExecutionTrace(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{Func: "sys_read", File: "fs/read_write.c"},
			{Func: "sys_read", File: "fs/read_write.c"},
			{Func: "rcu_read_lock", File: "kernel/rcu.c"}, // Noise.
			{Func: "vfs_read", File: "fs/read_write.c"},
			{Func: "trace_read", File: "fs/trace.c"}, // Noise.
			{Func: "vfs_read", File: "fs/read_write.c"},
			{Func: "fuse_read", File: "fs/fuse/file.c"}, // Deep call.
			{Func: "sys_read", File: "fs/read_write.c"}, // Return back to sys_read.
			{Func: "vfs_read", File: "fs/read_write.c"}, // Another call to vfs_read.
			{Func: ""},
			{Func: "sys_read", File: "fs/read_write.c"},
		},
		{
			{Func: "sys_write", File: "fs/read_write.c"},
			{Func: "vfs_write", File: "fs/read_write.c"},
		},
	}

	var deepCov []symbolizer.Frame
	for i := 0; i <= 55; i++ {
		deepCov = append(deepCov, symbolizer.Frame{Func: fmt.Sprintf("func_%d", i+1), File: "kernel/noise.c"})
	}
	dummyCov = append(dummyCov, deepCov)

	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc-3", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)

	// Test 1: Basic pseudo-call tree (no limits, no filters).
	idx := 0
	res, err := getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
	})
	require.NoError(t, err)
	require.Len(t, res.Traces, 1)
	require.Equal(t, 0, res.Traces[0].CallIndex)
	require.Equal(t, []string{
		"[1] sys_read", "[2] rcu_read_lock (context)", "[3] vfs_read",
		"[4] trace_read (context)", "[4] fuse_read", "[2] vfs_read",
	}, res.Traces[0].Trace)

	// Test 2: Filtering by subsystem.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		FilterSubsystem:   "fs/fuse/",
	})
	require.NoError(t, err)
	// Because MaxDepth for this trace is 4, all depths are <= 5, so all filtered calls become spine context.
	require.Equal(t, []string{
		"[1] sys_read (context)", "[2] rcu_read_lock (context)", "[3] vfs_read (context)",
		"[4] trace_read (context)", "[4] fuse_read", "[2] vfs_read (context)",
	}, res.Traces[0].Trace)

	// Test 3: FilterSubsystem bypasses noise filter for its own path.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		FilterSubsystem:   "kernel/rcu",
	})
	require.NoError(t, err)
	// rcu_read_lock is normally noise, but because it matches the subsystem, it is shown without (context).
	require.Equal(t, []string{
		"[1] sys_read (context)", "[2] rcu_read_lock", "[3] vfs_read (context)",
		"[4] trace_read (context)", "[4] fuse_read (context)", "[2] vfs_read (context)",
	}, res.Traces[0].Trace)

	// Test 4: IncludeNoise true includes all noise everywhere.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		IncludeNoise:      true,
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"[1] sys_read", "[2] rcu_read_lock", "[3] vfs_read",
		"[4] trace_read", "[4] fuse_read", "[2] vfs_read",
	}, res.Traces[0].Trace)

	// Test 5: Exponential Spine Context.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      2,
		FilterSubsystem:   "fs/fuse/", // filter doesn't match anything in deepCov
	})
	require.NoError(t, err)
	// maxDepth reached by deepCov is 56.
	// Spine depths: <=5, and 56-D = power of 2 (i.e. D=24, 40, 48, 52, 54, 55, 56).
	require.Equal(t, []string{
		"[1] func_1 (context)",
		"[2] func_2 (context)",
		"[3] func_3 (context)",
		"[4] func_4 (context)",
		"[5] func_5 (context)",
		"[24] func_24 (context)",
		"[40] func_40 (context)",
		"[48] func_48 (context)",
		"[52] func_52 (context)",
		"[54] func_54 (context)",
		"[55] func_55 (context)",
		"[56] func_56 (context)",
	}, res.Traces[0].Trace)

	// Test 6: Out of bounds index.
	idxOut := 5
	_, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idxOut,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SyscallIndex 5 is out of bounds")
}
