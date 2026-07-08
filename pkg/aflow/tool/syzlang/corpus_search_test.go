// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func createTestCorpusDir(t *testing.T, data syzspec.CorpusData, buckets []map[string]string) string {
	dir := t.TempDir()
	for i, b := range buckets {
		_, err := syzspec.SaveCorpusBucket(dir, i, b)
		require.NoError(t, err)
	}
	err := osutil.WriteJSON(filepath.Join(dir, "index.json"), data)
	require.NoError(t, err)
	return dir
}

func TestCorpusCodeSearch(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	bucket0 := map[string]string{
		"h1": "openat$kvm(0x1, 0x2)",
		"h2": "ioctl$KVM_CREATE_VM(0x3)",
	}
	bucket1 := map[string]string{
		"h3": "ioctl$KVM_RUN(0x4)\nopenat$kvm(0x5)",
	}

	cData := syzspec.CorpusData{
		FunctionMap: map[string][]string{
			"kvm_vcpu_ioctl": {"h2", "h3"},
			"kvm_vm_ioctl":   {"h1"},
		},
		SyscallMap: map[string][]string{
			"openat$kvm":          {"h1", "h3"},
			"ioctl$KVM_CREATE_VM": {"h2"},
			"ioctl$KVM_RUN":       {"h3"},
		},
		ProgToBucket: map[string]string{
			"h1": "bucket_000.json",
			"h2": "bucket_000.json",
			"h3": "bucket_001.json",
		},
	}

	dir := createTestCorpusDir(t, cData, []map[string]string{bucket0, bucket1})

	tests := []struct {
		name         string
		functionName string
		syscallName  string
		wantContains []string
		wantError    bool
	}{
		{
			name:         "only function name",
			functionName: "kvm_vcpu_ioctl",
			wantContains: []string{
				"Found 2 corpus programs reaching function \"kvm_vcpu_ioctl\"",
				"ioctl$KVM_CREATE_VM",
				"ioctl$KVM_RUN",
			},
		},
		{
			name:        "only syscall name exact",
			syscallName: "openat$kvm",
			wantContains: []string{
				"Found 2 corpus programs containing syscall matching \"openat$kvm\"",
				"openat$kvm(0x1, 0x2)",
				"ioctl$KVM_RUN(0x4)",
			},
		},
		{
			name:        "only syscall name substring case-insensitive",
			syscallName: "KVM",
			wantContains: []string{
				"Found 3 corpus programs containing syscall matching \"KVM\"",
				"openat$kvm(0x1, 0x2)",
				"ioctl$KVM_CREATE_VM",
				"ioctl$KVM_RUN",
			},
		},
		{
			name:         "both function and syscall (error)",
			functionName: "kvm_vcpu_ioctl",
			syscallName:  "openat$kvm",
			wantError:    true,
		},
		{
			name:      "both empty (error)",
			wantError: true,
		},
		{
			name:         "no matches",
			functionName: "non_existent_function",
			wantContains: []string{
				"No corpus programs found reaching function \"non_existent_function\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := CorpusCodeSearchState{CorpusDir: dir}
			args := CorpusCodeSearchArgs{
				FunctionName: tt.functionName,
				SyscallName:  tt.syscallName,
			}
			res, err := corpusCodeSearch(ctx, state, args)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				for _, expected := range tt.wantContains {
					require.Contains(t, res.Output, expected)
				}
			}
		})
	}
}

func TestCorpusCodeSearch_DeterministicOrder(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	bucket0 := map[string]string{
		"p1": "call1()",
		"p2": "call2()",
		"p3": "call3()",
		"p4": "call4()",
	}
	bucket1 := map[string]string{
		"p5": "call5()",
		"p6": "call6()",
		"p7": "call7()",
	}

	cData := syzspec.CorpusData{
		FunctionMap: map[string][]string{
			"foo": {"p1", "p2", "p3", "p4", "p5", "p6", "p7"},
		},
		SyscallMap: map[string][]string{
			"call_a": {"p1", "p3", "p7"},
			"call_b": {"p2", "p4", "p5", "p6"},
		},
		ProgToBucket: map[string]string{
			"p1": "bucket_000.json", "p2": "bucket_000.json", "p3": "bucket_000.json", "p4": "bucket_000.json",
			"p5": "bucket_001.json", "p6": "bucket_001.json", "p7": "bucket_001.json",
		},
	}

	dir := createTestCorpusDir(t, cData, []map[string]string{bucket0, bucket1})

	state := CorpusCodeSearchState{CorpusDir: dir}
	args := CorpusCodeSearchArgs{SyscallName: "call"}

	// Run multiple times to verify deterministic output across map iterations.
	for range 10 {
		res, err := corpusCodeSearch(ctx, state, args)
		require.NoError(t, err)
		require.Contains(t, res.Output, "Found 7 corpus programs")
		require.Contains(t, res.Output, "Showing the first 5 programs")
		require.Contains(t, res.Output, "=== Program 1 ===\ncall1()")
		require.Contains(t, res.Output, "=== Program 2 ===\ncall2()")
		require.Contains(t, res.Output, "=== Program 3 ===\ncall3()")
		require.Contains(t, res.Output, "=== Program 4 ===\ncall4()")
		require.Contains(t, res.Output, "=== Program 5 ===\ncall5()")
		require.NotContains(t, res.Output, "call6()")
		require.NotContains(t, res.Output, "call7()")
	}
}

func TestCorpusCodeSearch_EmptyState(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	res, err := corpusCodeSearch(ctx, CorpusCodeSearchState{}, CorpusCodeSearchArgs{FunctionName: "foo"})
	require.NoError(t, err)
	require.Contains(t, res.Output, "No corpus directory provided")
}

func TestCorpusCodeSearch_InvalidDir(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	_, err := corpusCodeSearch(ctx, CorpusCodeSearchState{CorpusDir: filepath.Join(t.TempDir(), "nonexistent")},
		CorpusCodeSearchArgs{FunctionName: "foo"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read corpus execution data")
}
