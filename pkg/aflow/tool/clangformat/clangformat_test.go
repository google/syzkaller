// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package clangformat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestClangFormat(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "repo")
	require.NoError(t, os.MkdirAll(filepath.Join(repoDir, "arch/arm64/kernel"), 0755))

	// Create a .clang-format in repo root.
	require.NoError(t, osutil.WriteFile(filepath.Join(repoDir, ".clang-format"), []byte(`BasedOnStyle: LLVM
IndentWidth: 8
UseTab: Always
ColumnLimit: 80
BreakBeforeBraces: Linux
`)))

	// Verify that a 96-character line is not wrapped, confirming the ColumnLimit: 100 override.
	testFile := filepath.Join(repoDir, "arch/arm64/kernel/test.c")
	code := `
int long_function_name(int first_argument_name, int second_argument_name, int third_argument_name) {
    int x = 1;
    int y = 2;
    return x + y;
}
`[1:]
	require.NoError(t, osutil.WriteFile(testFile, []byte(code)))

	aflow.TestTool(t, Tool,
		state{KernelScratchSrc: repoDir},
		args{File: "arch/arm64/kernel/test.c"},
		func(res result) {
			content, err := os.ReadFile(testFile)
			require.NoError(t, err)
			expected := `
int long_function_name(int first_argument_name, int second_argument_name, int third_argument_name)
{
	int x = 1;
	int y = 2;
	return x + y;
}
`[1:]
			require.Equal(t, expected, string(content))
		},
		"", aflow.TestWorkdir(tmpDir))
}
