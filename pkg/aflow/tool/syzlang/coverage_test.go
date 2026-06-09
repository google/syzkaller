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
	res, err := getCoverageFiles(ctx,
		reproduceState{TargetOS: "linux", TargetArch: "amd64"},
		CoverageFilesArgs{ExecutionCachedID: reproExecCachedID})
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

		Filename: "foo.c",
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

		Filename: "nonexistent.c",
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

		Filename:  "foo.c",
		Functions: []string{"foo", "nonexistent_function"},
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

		SyscallIndex: idx,
	})
	require.NoError(t, err)
	require.Len(t, res.Traces, 1)
	require.Equal(t, 0, res.Traces[0].CallIndex)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c)", "vfs_read (fs/read_write.c)",
		"fuse_read (fs/fuse/file.c)", "sys_read (fs/read_write.c)",
		"vfs_read (fs/read_write.c)", "sys_read (fs/read_write.c)",
	}, res.Traces[0].Trace)

	// Test 2: Filtering by subsystem.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,

		SyscallIndex:    idx,
		FilterSubsystem: "fs/fuse/",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c) (context)", "vfs_read (fs/read_write.c) (context)",
		"fuse_read (fs/fuse/file.c)", "sys_read (fs/read_write.c) (context)",
		"vfs_read (fs/read_write.c) (context)", "sys_read (fs/read_write.c) (context)",
	}, res.Traces[0].Trace)

	// Test 3: FilterSubsystem bypasses noise filter for its own path.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,

		SyscallIndex:    idx,
		FilterSubsystem: "kernel/rcu",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c) (context)", "rcu_read_lock (kernel/rcu.c)",
		"vfs_read (fs/read_write.c) (context)",
	}, res.Traces[0].Trace)

	// Test 4: IncludeNoise true includes all noise everywhere.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,

		SyscallIndex: idx,
		IncludeNoise: true,
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c)", "rcu_read_lock (kernel/rcu.c)",
		"vfs_read (fs/read_write.c)", "trace_read (fs/trace.c)",
		"vfs_read (fs/read_write.c)", "fuse_read (fs/fuse/file.c)",
		"sys_read (fs/read_write.c)", "vfs_read (fs/read_write.c)",
		"sys_read (fs/read_write.c)",
	}, res.Traces[0].Trace)

	// Test 5: FilterSubsystem with zero matches returns head (10) and tail (10) context.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      -1,
		FilterSubsystem:   "fs/fuse/", // filter doesn't match anything in deepCov
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"func_1 (kernel/noise.c) (context)",
		"func_2 (kernel/noise.c) (context)",
		"func_3 (kernel/noise.c) (context)",
		"func_4 (kernel/noise.c) (context)",
		"func_5 (kernel/noise.c) (context)",
		"func_6 (kernel/noise.c) (context)",
		"func_7 (kernel/noise.c) (context)",
		"func_8 (kernel/noise.c) (context)",
		"func_9 (kernel/noise.c) (context)",
		"func_10 (kernel/noise.c) (context)",
		"... [no filter match; 36 lines omitted] ...",
		"func_47 (kernel/noise.c) (context)",
		"func_48 (kernel/noise.c) (context)",
		"func_49 (kernel/noise.c) (context)",
		"func_50 (kernel/noise.c) (context)",
		"func_51 (kernel/noise.c) (context)",
		"func_52 (kernel/noise.c) (context)",
		"func_53 (kernel/noise.c) (context)",
		"func_54 (kernel/noise.c) (context)",
		"func_55 (kernel/noise.c) (context)",
		"func_56 (kernel/noise.c) (context)",
	}, res.Traces[0].Trace)

	// Test 6: Out of bounds index.
	idxOut := 5
	_, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,

		SyscallIndex: idxOut,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SyscallIndex 5 is out of bounds")

	// Test 7: Extra coverage index passed explicitly (should fail).
	// dummyCov has length 3 (index 2 is extra coverage, valid syscall indices are 0-1).
	_, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      2,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SyscallIndex 2 is out of bounds (0-1). Use -1 for extra coverage.")

	// Test 8: GrepPattern substring match on function name.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		GrepPattern:       "fuse_",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c) (context)", "vfs_read (fs/read_write.c) (context)",
		"fuse_read (fs/fuse/file.c)  <-- MATCH", "sys_read (fs/read_write.c) (context)",
		"vfs_read (fs/read_write.c) (context)", "sys_read (fs/read_write.c) (context)",
	}, res.Traces[0].Trace)

	// Test 9: GrepPattern regex match.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		GrepPattern:       "vfs_.*",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c) (context)",
		"vfs_read (fs/read_write.c)  <-- MATCH",
		"vfs_read (fs/read_write.c)  <-- MATCH", "fuse_read (fs/fuse/file.c) (context)",
		"sys_read (fs/read_write.c) (context)", "vfs_read (fs/read_write.c)  <-- MATCH",
		"sys_read (fs/read_write.c) (context)",
	}, res.Traces[0].Trace)

	// Test 10: GrepPattern match on file path.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		GrepPattern:       "fs/read_write.c",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"sys_read (fs/read_write.c)  <-- MATCH",
		"vfs_read (fs/read_write.c)  <-- MATCH",
		"vfs_read (fs/read_write.c)  <-- MATCH", "fuse_read (fs/fuse/file.c) (context)",
		"sys_read (fs/read_write.c)  <-- MATCH", "vfs_read (fs/read_write.c)  <-- MATCH",
		"sys_read (fs/read_write.c)  <-- MATCH",
	}, res.Traces[0].Trace)

	// Test 11: Invalid GrepPattern regex error.
	_, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      idx,
		GrepPattern:       "[invalid(",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid GrepPattern regex")

	// Test 12: Offset and Limit pagination.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      0,
		Offset:            2,
		Limit:             2,
	})
	require.NoError(t, err)
	require.Len(t, res.Traces, 1)
	require.Equal(t, []string{
		"... [trace started from line 2. 2 lines omitted before this] ...",
		"fuse_read (fs/fuse/file.c)",
		"sys_read (fs/read_write.c)",
		"... [trace truncated. 2 lines remaining. Use get-execution-trace with Offset=4 and Limit=2 to view next part] ...",
	}, res.Traces[0].Trace)

	// Test 13: Global truncation (trace > 1000 lines) without pagination parameters.
	var longCov []symbolizer.Frame
	for i := range 1100 {
		longCov = append(longCov, symbolizer.Frame{Func: fmt.Sprintf("func_%d", i+1), File: "fs/fuse/file.c"})
	}
	_, reproExecCachedIDLong, err := aflow.CacheObject(ctx, "repro", "dummy-desc-long", func() (map[string]any, error) {
		return map[string]any{"Coverage": [][]symbolizer.Frame{longCov, nil}}, nil
	})
	require.NoError(t, err)

	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedIDLong,
		SyscallIndex:      0,
	})
	require.NoError(t, err)
	require.Len(t, res.Traces, 1)
	require.Len(t, res.Traces[0].Trace, 1001) // 500 head + 1 message + 500 tail.
	require.Equal(t, "func_1 (fs/fuse/file.c)", res.Traces[0].Trace[0])
	require.Contains(t, res.Traces[0].Trace[500], "... [trace truncated. 100 lines omitted (lines 500 to 599).")
	require.Equal(t, "func_1100 (fs/fuse/file.c)", res.Traces[0].Trace[1000])

	// Test 14: Background coverage (index -1) without filters.
	res, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      -1,
	})
	require.NoError(t, err)
	require.Len(t, res.Traces, 1)
	require.Equal(t, -1, res.Traces[0].CallIndex)
	require.Len(t, res.Traces[0].Trace, 56)
	require.Equal(t, "func_1 (kernel/noise.c)", res.Traces[0].Trace[0])
	require.Equal(t, "func_56 (kernel/noise.c)", res.Traces[0].Trace[55])
}

func TestExecutionTraceNoCoverage(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	_, reproExecCachedID, err := aflow.CacheObject(ctx, "repro", "dummy-desc-empty", func() (map[string]any, error) {
		return map[string]any{"Coverage": [][]symbolizer.Frame{}}, nil
	})
	require.NoError(t, err)
	_, err = getExecutionTrace(ctx, reproduceState{}, ExecutionTraceArgs{
		ExecutionCachedID: reproExecCachedID,
		SyscallIndex:      -1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no coverage data available")
}

func TestIsNoiseFunction(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"arch_prctl", false},
		{"sys_arch_prctl", false},
		{"do_arch_prctl", false},
		{"arch_ptrace", false},
		{"arch_do_signal_or_restart", false},
		{"arch_setup_additional_pages", false},
		{"arch_spin_lock", true},
		{"arch_spin_unlock", true},
		{"arch_raw_spin_lock", true},
		{"arch_local_irq_save", true},
		{"arch_atomic_read", true},
		{"arch_cmpxchg", true},
		{"arch_cpu_idle", true},
		{"arch_mutex_lock", true},
		{"arch_static_branch", true},
		{"rcu_read_lock", true},
		{"printk", false},
		{"printk_deferred", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isNoiseFunction(tt.name))
		})
	}
}
