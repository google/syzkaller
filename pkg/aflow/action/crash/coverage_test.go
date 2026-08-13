// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/stretchr/testify/require"
)

func TestParseHexPC(t *testing.T) {
	tests := []struct {
		input   string
		want    uint64
		wantErr bool
	}{
		{"0x1000", 0x1000, false},
		{"0X1000", 0x1000, false},
		{"1000", 0x1000, false},
		{"  0xffffffff81001234  ", 0xffffffff81001234, false},
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseHexPC(tt.input)
		if tt.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		}
	}
}

func TestCheckPCsInCoverage(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{PC: 0x100, Func: "foo", File: "kernel/foo.c", Line: 10},
			{PC: 0x200, Func: "bar", File: "kernel/bar.c", Line: 20},
		},
		{
			{PC: 0x300, Func: "baz", File: "kernel/baz.c", Line: 30},
		},
	}

	_, cachedID, err := aflow.CacheObject(ctx, "repro", "test-cov", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		targetPCs []uint64
		want      bool
	}{
		{
			name:      "single PC hit",
			targetPCs: []uint64{0x200},
			want:      true,
		},
		{
			name:      "single PC miss",
			targetPCs: []uint64{0x999},
			want:      false,
		},
		{
			name:      "multiple PCs with hit",
			targetPCs: []uint64{0x999, 0x300, 0x888},
			want:      true,
		},
		{
			name:      "multiple PCs with no hit",
			targetPCs: []uint64{0x999, 0x888},
			want:      false,
		},
		{
			name:      "empty target PCs",
			targetPCs: nil,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached, err := CheckPCsInCoverage(ctx, cachedID, tt.targetPCs...)
			require.NoError(t, err)
			require.Equal(t, tt.want, reached)
		})
	}
}

func TestCheckHexPCsInCoverage(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	dummyCov := [][]symbolizer.Frame{
		{
			{PC: 0x100, Func: "foo", File: "kernel/foo.c", Line: 10},
			{PC: 0x200, Func: "bar", File: "kernel/bar.c", Line: 20},
		},
	}

	_, cachedID, err := aflow.CacheObject(ctx, "repro", "test-hex-cov", func() (map[string]any, error) {
		return map[string]any{"Coverage": dummyCov}, nil
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		targetPCs []string
		want      bool
		wantErr   bool
	}{
		{
			name:      "valid hex hit",
			targetPCs: []string{"0x999", "0x100"},
			want:      true,
		},
		{
			name:      "invalid hex format",
			targetPCs: []string{"0x999", "invalid_pc"},
			wantErr:   true,
		},
		{
			name:      "empty target PCs",
			targetPCs: nil,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached, err := CheckHexPCsInCoverage(ctx, cachedID, tt.targetPCs...)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, reached)
			}
		})
	}
}
