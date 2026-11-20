// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestCreateSourceFile(t *testing.T) {
	dir := osutil.SandboxTempDir(t)
	t.Setenv("HOME", dir)
	repo := vcs.MakeTestRepo(t, filepath.Join(dir, "repo"))
	repo.CommitChangeset("initial commit", vcs.FileContent{File: "old.c", Content: "int old;\n"})
	const name = "-new.c"
	aflow.TestTool(t, CreateTool, state{repo.Dir}, createArgs{name, "int value;"}, struct{}{}, "")
	filename := filepath.Join(repo.Dir, name)
	t.Run("ownership", func(t *testing.T) {
		osutil.RequireSandbox(t)
		require.True(t, osutil.IsSandboxOwned(t, filename))
	})
	aflow.TestTool(t, CreateTool, state{repo.Dir}, createArgs{name, "int overwrite;"}, struct{}{},
		`failed to create source file "-new.c":`, aflow.TestErrorPrefix())
	aflow.TestTool(t, Tool, state{repo.Dir}, args{
		SourceFile:  name,
		CurrentCode: "int value;",
		NewCode:     "int updated;",
	}, struct{}{}, "")
	diff, err := patchdiff.Diff(repo.Dir, "HEAD")
	require.NoError(t, err)
	require.Contains(t, diff, "new file mode 100644")
	require.Contains(t, diff, "+++ b/-new.c")
	require.Contains(t, diff, "+int updated;\n")
	other := vcs.MakeTestRepo(t, filepath.Join(dir, "other"))
	require.NoError(t, vcs.SandboxedGit(other.Dir).Apply([]byte(diff)))
	data, err := os.ReadFile(filepath.Join(other.Dir, name))
	require.NoError(t, err)
	require.Equal(t, "int updated;\n", string(data))
}

func TestCreateSourceFileRejectsInvalidPath(t *testing.T) {
	for _, name := range []string{"../new.c", "/new.c", ".git/new.c", "a/../new.c", "a//new.c", "bad*.c", "new.txt"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			aflow.TestTool(t, CreateTool, state{dir}, createArgs{name, "int value;"},
				struct{}{}, "invalid source file path", aflow.TestErrorPrefix())
		})
	}
}

func TestCreateSourceFileDoesNotFollowLinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "outside")))
	require.NoError(t, os.Symlink("target.c", filepath.Join(dir, "link.c")))
	for _, name := range []string{"outside/new.c", "link.c"} {
		aflow.TestTool(t, CreateTool, state{dir}, createArgs{name, "int value;"},
			struct{}{}, "failed to create source file", aflow.TestErrorPrefix())
	}
	require.NoFileExists(t, filepath.Join(outside, "new.c"))
	require.NoFileExists(t, filepath.Join(dir, "target.c"))
}
