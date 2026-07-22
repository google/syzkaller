// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:  "hex with 0x prefix",
			input: "0xffffffff80000000",
			want:  0xffffffff80000000,
		},
		{
			name:  "hex without 0x prefix",
			input: "ffffffff80000000",
			want:  0xffffffff80000000,
		},
		{
			name:  "raw uint (decimal string matching 0xffffffff80000000)",
			input: "18446744071562067968",
			want:  0xffffffff80000000,
		},
		{
			name:  "hex with 0x prefix and spaces",
			input: "  0xffffffff80000000  ",
			want:  0xffffffff80000000,
		},
		{
			name:  "small decimal uint",
			input: "12345",
			want:  12345,
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

func TestGetEnvironment(t *testing.T) {
	state := EnvironmentState{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Type:       "qemu",
		VM: json.RawMessage(`{
			"cmdline": "root=/dev/sda1 dummy_hcd.num=1",
			"qemu_args": "-enable-kvm -m 4096M"
		}`),
	}

	res, err := getEnvironmentAction(nil, state, EnvironmentArgs{})
	require.NoError(t, err)
	require.Contains(t, res.Output, "Target OS: linux")
	require.Contains(t, res.Output, "Target Arch: amd64")
	require.Contains(t, res.Output, "VM Type: qemu")
	require.Contains(t, res.Output, "VM Cmdline: root=/dev/sda1 dummy_hcd.num=1")
	require.Contains(t, res.Output, "VM Qemu Args: -enable-kvm -m 4096M")
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
