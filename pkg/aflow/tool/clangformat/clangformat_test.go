// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package clangformat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClangFormat(t *testing.T) {
	tmpDir := osutil.SandboxTempDir(t)
	repoDir := filepath.Join(tmpDir, "repo")
	kernelDir := filepath.Join(repoDir, "arch/arm64/kernel")
	require.NoError(t, os.MkdirAll(kernelDir, 0755))

	// Create a .clang-format in repo root.
	require.NoError(t, osutil.WriteFile(filepath.Join(repoDir, ".clang-format"), []byte(`BasedOnStyle: LLVM
IndentWidth: 8
UseTab: Always
ColumnLimit: 80
BreakBeforeBraces: Linux
`)))

	// Verify that a 96-character line is not wrapped, confirming the ColumnLimit: 100 override.
	testFile := filepath.Join(kernelDir, "test.c")
	code := `
int long_function_name(int first_argument_name, int second_argument_name, int third_argument_name) {
    int x = 1;
    int y = 2;
    return x + y;
}
`[1:]
	require.NoError(t, osutil.WriteFile(testFile, []byte(code)))
	t.Run("sandbox", func(t *testing.T) {
		osutil.RequireSandbox(t)
		_, err := aflow.TestToolRun(Tool,
			map[string]any{"KernelScratchSrc": repoDir},
			map[string]any{"File": "arch/arm64/kernel/test.c"})
		require.Error(t, err)
		assert.Contains(t, osutil.VerboseMessage(err), "Permission denied")
	})
	require.NoError(t, osutil.SandboxChown(testFile, kernelDir))

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

func TestClangFormatBadFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "tree", "sub"), 0755))
	require.NoError(t, osutil.WriteFile(filepath.Join(dir, "outside.c"), []byte("int  x;\n")))
	require.NoError(t, os.Symlink(filepath.Join(dir, "outside.c"), filepath.Join(dir, "tree", "link.c")))
	require.NoError(t, os.Symlink(dir, filepath.Join(dir, "tree", "updir")))
	tree := filepath.Join(dir, "tree")
	for _, test := range []struct {
		file string
		err  string
	}{
		{"../outside.c", `File "../outside.c" is outside of the source tree`},
		{"/etc/passwd", `File "/etc/passwd" is outside of the source tree`},
		{"link.c", `File "link.c" does not exist`},
		{"updir/outside.c", `File "updir/outside.c" does not exist`},
		{"sub", `File "sub" does not exist`},
	} {
		t.Run(test.file, func(t *testing.T) {
			aflow.TestTool(t, Tool, state{KernelScratchSrc: tree}, args{File: test.file}, result{}, test.err)
		})
	}
	content, err := os.ReadFile(filepath.Join(dir, "outside.c"))
	require.NoError(t, err)
	require.Equal(t, "int  x;\n", string(content))
}
