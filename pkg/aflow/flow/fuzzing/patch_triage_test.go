// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeKernelConfigs(t *testing.T) {
	configs := []string{"CONFIG_FOO_BAR", "BAZ", "CONFIG_QUX"}
	want := []string{"FOO_BAR", "BAZ", "QUX"}
	got := normalizeKernelConfigs(configs)
	require.Equal(t, want, got)
}

func TestValidateKernelConfigs(t *testing.T) {
	dir := t.TempDir()
	kconfigContent := `
mainmenu "test"

config FOO_BAR
	bool "foo bar"

config BAZ
	bool "baz"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Kconfig"), []byte(kconfigContent), 0644))

	tests := []struct {
		name    string
		configs []string
		wantErr string
	}{
		{
			name:    "empty",
			configs: []string{},
		},
		{
			name:    "valid",
			configs: []string{"FOO_BAR", "BAZ"},
		},
		{
			name:    "single invalid",
			configs: []string{"FOO_BAR", "INVALID"},
			wantErr: `the following configs do not exist in the kernel tree: INVALID`,
		},
		{
			name:    "multiple invalid",
			configs: []string{"INVALID1", "FOO_BAR", "INVALID2"},
			wantErr: `the following configs do not exist in the kernel tree: INVALID1, INVALID2`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKernelConfigs("amd64", dir, tc.configs)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
