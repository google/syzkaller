// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandFileInputs(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test.config")
	configContent := "CONFIG_TEST=y\nCONFIG_FOO=n\n"
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	crashFile := filepath.Join(tempDir, "crash.log")
	crashContent := "BUG: unable to handle kernel paging request"
	err = os.WriteFile(crashFile, []byte(crashContent), 0644)
	require.NoError(t, err)

	subDir := filepath.Join(tempDir, "sub")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)
	reproFile := filepath.Join(subDir, "repro.c")
	reproContent := "int main() { return 0; }"
	err = os.WriteFile(reproFile, []byte(reproContent), 0644)
	require.NoError(t, err)

	tests := []struct {
		name      string
		inputs    map[string]any
		baseDir   string
		want      map[string]any
		expectErr bool
	}{
		{
			name: "no-at-prefix",
			inputs: map[string]any{
				"BugTitle":     "KASAN: use-after-free",
				"KernelConfig": "CONFIG_TEST=y\n",
				"Count":        42,
				"Enabled":      true,
			},
			baseDir: tempDir,
			want: map[string]any{
				"BugTitle":     "KASAN: use-after-free",
				"KernelConfig": "CONFIG_TEST=y\n",
				"Count":        42,
				"Enabled":      true,
			},
		},
		{
			name: "absolute-path",
			inputs: map[string]any{
				"KernelConfig": "@" + configFile,
			},
			baseDir: "",
			want: map[string]any{
				"KernelConfig": configContent,
			},
		},
		{
			name: "relative-path",
			inputs: map[string]any{
				"CrashReport": "@crash.log",
				"ReproC":      "@sub/repro.c",
			},
			baseDir: tempDir,
			want: map[string]any{
				"CrashReport": crashContent,
				"ReproC":      reproContent,
			},
		},
		{
			name: "escaped-at-prefix",
			inputs: map[string]any{
				"Mention": "@@developer",
			},
			baseDir: tempDir,
			want: map[string]any{
				"Mention": "@developer",
			},
		},
		{
			name: "nested-map-and-slice",
			inputs: map[string]any{
				"VM": map[string]any{
					"Config": "@test.config",
				},
				"ExtraFiles": []any{
					"@crash.log",
					"regular_string",
					"@@literal_at",
				},
				"NestedMatrix": []any{
					[]any{
						"@crash.log",
						"@@escape",
					},
				},
			},
			baseDir: tempDir,
			want: map[string]any{
				"VM": map[string]any{
					"Config": configContent,
				},
				"ExtraFiles": []any{
					crashContent,
					"regular_string",
					"@literal_at",
				},
				"NestedMatrix": []any{
					[]any{
						crashContent,
						"@escape",
					},
				},
			},
		},
		{
			name: "missing-file-error",
			inputs: map[string]any{
				"KernelConfig": "@non_existent_file.config",
			},
			baseDir:   tempDir,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := expandFileInputs(tc.inputs, tc.baseDir)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, tc.inputs)
			}
		})
	}
}
