// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveKernelConfigPath(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test.config")
	configContent := "CONFIG_TEST=y\nCONFIG_FOO=n\n"
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	executeTestContent, err := os.ReadFile("execute_test.go")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		inputs    map[string]any
		wantVal   string
		expectErr bool
	}{
		{
			name: "no-config",
			inputs: map[string]any{
				"KernelRepo": "some-repo",
			},
			wantVal: "",
		},
		{
			name: "inline-config",
			inputs: map[string]any{
				"KernelConfig": "CONFIG_INLINE=y\nCONFIG_BAR=y",
			},
			wantVal: "CONFIG_INLINE=y\nCONFIG_BAR=y",
		},
		{
			name: "absolute-path",
			inputs: map[string]any{
				"KernelConfig": configFile,
			},
			wantVal: configContent,
		},
		{
			name: "relative-path",
			inputs: map[string]any{
				"KernelConfig": "execute_test.go",
			},
			wantVal: string(executeTestContent),
		},
		{
			name: "single-line-config-contains-equals",
			inputs: map[string]any{
				"KernelConfig": "CONFIG_TEST=y",
			},
			wantVal: "CONFIG_TEST=y",
		},
		{
			name: "non-existent-path-treated-as-path",
			inputs: map[string]any{
				"KernelConfig": "non_existent.config",
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputs := maps.Clone(tc.inputs)

			err := resolveKernelConfigPath(inputs)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if val, ok := inputs["KernelConfig"]; ok {
					assert.Equal(t, tc.wantVal, val)
				} else {
					assert.Empty(t, tc.wantVal)
				}
			}
		})
	}
}
