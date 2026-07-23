// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/stretchr/testify/require"
)

func TestParsePC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "hex with 0x prefix",
			input: "0xffffffff80000000",
			want:  "0xffffffff80000000",
		},
		{
			name:  "hex without 0x prefix",
			input: "ffffffff80000000",
			want:  "0xffffffff80000000",
		},
		{
			name:  "raw uint (decimal string matching 0xffffffff80000000)",
			input: "18446744071562067968",
			want:  "0xffffffff80000000",
		},
		{
			name:  "hex with 0x prefix and spaces",
			input: "  0xffffffff80000000  ",
			want:  "0xffffffff80000000",
		},
		{
			name:  "small decimal uint",
			input: "12345",
			want:  "0x3039",
		},
		{
			name:    "invalid input",
			input:   "not_a_number",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := ParsePCArgs{RawPC: tt.input}
			got, err := parsePCAction(nil, args)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got.PC)
			}
		})
	}
}

func TestResolveLineToPCAction(t *testing.T) {
	// Test missing parameters error.
	_, err := resolveLineToPCAction(nil, ResolveLineToPCArgs{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "both FilePath and LineNumber must be provided")

	// Test invalid line number error.
	_, err = resolveLineToPCAction(nil, ResolveLineToPCArgs{FilePath: "fs/ext4/super.c", LineNumber: 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "both FilePath and LineNumber must be provided")
}

func TestMatchDwarfFile(t *testing.T) {
	kd := &mgrconfig.KernelDirs{}
	require.True(t, matchDwarfFile("arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", kd))
	require.True(t, matchDwarfFile("/build/kernel/arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", kd))
	require.False(t, matchDwarfFile("fs/ext4/super.c", "fs/ext4/inode.c", kd))
}
