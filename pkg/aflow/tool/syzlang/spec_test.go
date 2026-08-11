// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func syzkallerRepoRoot(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod not found")
		}
		dir = parent
	}
}

func TestDescriptionFiles(t *testing.T) {
	syzFS := syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)
	files := syzFS.DescriptionFiles()
	require.Greater(t, len(files), 50)
	require.Contains(t, files, "sys.txt")
}

func TestDescriptionFilesPrompt(t *testing.T) {
	syzFS := syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)
	prompt := DescriptionFilesPrompt(syzFS)
	require.Contains(t, prompt, "Available Syscall Description Files:\n")
	require.Contains(t, prompt, "sys.txt\n")
	require.NotContains(t, prompt, "sys.txt.const\n")
}

func TestTestSeeds(t *testing.T) {
	syzFS := syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)
	seeds := syzFS.TestSeeds()
	require.NotEmpty(t, seeds)
	require.Contains(t, seeds, "test/syz_mount_image_btrfs_0")

	legacySeeds := TestSeeds(syzkallerRepoRoot(t), targets.Linux)
	require.Equal(t, seeds, legacySeeds)
}

func TestReadSyzSpec(t *testing.T) {
	state := specToolsState{SyzFS: syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)}
	// Test pagination.
	res, err := readSyzSpec(nil, state, readSyzSpecArgs{
		File:      "sys.txt",
		FirstLine: 1,
	})
	require.NoError(t, err)
	require.Contains(t, res.Output, "Copyright")

	// Test missing file.
	_, err2 := readSyzSpec(nil, state, readSyzSpecArgs{File: "non_existent_file.txt"})
	require.Error(t, err2)

	// Test invalid file paths.
	_, errInvalid := readSyzSpec(nil, state, readSyzSpecArgs{File: "../sys.txt"})
	require.ErrorContains(t, errInvalid, "invalid file path")
	_, errInvalid2 := readSyzSpec(nil, state, readSyzSpecArgs{File: "/etc/passwd"})
	require.ErrorContains(t, errInvalid2, "invalid file path")

	// Test reading auto.txt or auto.txt.const is disallowed.
	_, errAuto := readSyzSpec(nil, state, readSyzSpecArgs{File: "auto.txt"})
	require.ErrorContains(t, errAuto, "access to auto.txt or auto.txt.const is disallowed")
	_, errAutoConst := readSyzSpec(nil, state, readSyzSpecArgs{File: "auto.txt.const"})
	require.ErrorContains(t, errAutoConst, "access to auto.txt or auto.txt.const is disallowed")

	// Test reading const file works.
	resConst, errConst := readSyzSpec(nil, state, readSyzSpecArgs{File: "aio.txt.const", FirstLine: 1})
	require.NoError(t, errConst)
	require.NotEmpty(t, resConst.Output)

	// Test pagination boundary violation.
	_, errBound := readSyzSpec(nil, state, readSyzSpecArgs{
		File:      "sys.txt",
		FirstLine: 9999999, // Way out of bounds.
	})
	require.ErrorContains(t, errBound, "does not have line")

	// Test reading test seed file.
	testRepoState := specToolsState{SyzFS: syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)}
	resSeed, errSeed := readSyzSpec(nil, testRepoState, readSyzSpecArgs{
		File:      "test/syz_mount_image_btrfs_0",
		FirstLine: 1,
	})
	require.NoError(t, errSeed)
	require.NotEmpty(t, resSeed.Output)

	// Test pagination of mock file inside executor/.
	resExec, errExec := readSyzSpec(nil, testRepoState, readSyzSpecArgs{
		File:      "executor/common.h",
		FirstLine: 1,
	})
	require.NoError(t, errExec)
	require.Contains(t, resExec.Output, "doexit_thread")

	// Test rejection of path traversal attempts.
	_, errTrav := readSyzSpec(nil, testRepoState, readSyzSpecArgs{File: "executor/../../configs/something.conf"})
	require.ErrorContains(t, errTrav, "invalid file path")
}

func TestSyzGrepper(t *testing.T) {
	state := specToolsState{SyzFS: syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)}
	// Test grep with a file.
	resGrep, errGrep := syzGrepper(nil, state, syzGrepperArgs{
		PathPrefix: "sys.txt",
		Expression: "^type ",
	})
	require.NoError(t, errGrep)
	require.Contains(t, resGrep.Output, "type ")
	require.Contains(t, resGrep.Output, ":\ttype")

	// Test grep across all files.
	resGrepAll, errGrepAll := syzGrepper(nil, state, syzGrepperArgs{
		Expression: "^type ",
	})
	require.NoError(t, errGrepAll)
	require.Contains(t, resGrepAll.Output, "binfmt.txt:")
	require.NotContains(t, resGrepAll.Output, "linux/binfmt.txt:")
	require.Contains(t, resGrepAll.Output, "type")

	// Test grep with no matches (should return success, not error).
	resEmpty, errEmpty := syzGrepper(nil, state, syzGrepperArgs{
		PathPrefix: "sys.txt",
		Expression: "THIS_STRING_SHOULD_NOT_EXIST_IN_SYS_TXT",
	})
	require.NoError(t, errEmpty)
	require.Equal(t, "No matches found.", resEmpty.Output)

	// Test grep across test seed file.
	testRepoState := specToolsState{SyzFS: syzspec.NewSyzFS(syzkallerRepoRoot(t), targets.Linux)}
	resSeedGrep, errSeedGrep := syzGrepper(nil, testRepoState, syzGrepperArgs{
		PathPrefix: "test/syz_mount_image_btrfs_0",
		Expression: "syz_mount_image",
	})
	require.NoError(t, errSeedGrep)
	require.Contains(t, resSeedGrep.Output, "syz_mount_image")

	// Test grep across test directory (multiple files).
	resDirGrep, errDirGrep := syzGrepper(nil, testRepoState, syzGrepperArgs{
		PathPrefix: "test",
		Expression: "syz_mount_image",
	})
	require.NoError(t, errDirGrep)
	require.Contains(t, resDirGrep.Output, "test/syz_mount_image_btrfs_0:")
	require.NotContains(t, resDirGrep.Output, "linux/test/syz_mount_image_btrfs_0:")

	// Test grepping across files in executor/.
	resExecGrep, errExecGrep := syzGrepper(nil, testRepoState, syzGrepperArgs{
		PathPrefix: "executor/common.h",
		Expression: "doexit_thread",
	})
	require.NoError(t, errExecGrep)
	require.Contains(t, resExecGrep.Output, "doexit_thread")

	// Test grepping with PathPrefix "." does not scan auto.txt.
	resDotGrep, errDotGrep := syzGrepper(nil, testRepoState, syzGrepperArgs{
		PathPrefix: ".",
		Expression: "meta automatic",
	})
	require.NoError(t, errDotGrep)
	require.NotContains(t, resDotGrep.Output, "meta automatic")
	require.Equal(t, "No matches found.", resDotGrep.Output)
}

func TestCleanPath_TrailingSlash(t *testing.T) {
	t.Parallel()

	syzFS := syzspec.NewSyzFS(syzkallerRepoRoot(t), "linux")

	require.Equal(t, "", syzFS.CleanPath("sys/linux/"))
	require.Equal(t, "", syzFS.CleanPath("sys/linux"))
	require.Equal(t, "vusb.txt", syzFS.CleanPath("sys/linux/vusb.txt"))
	require.Equal(t, "test/vusb_hid", syzFS.CleanPath("sys/linux/test/vusb_hid"))
}

func TestSanitizeError_NoHostPathLeak(t *testing.T) {
	t.Parallel()

	state := specToolsState{
		SyzFS: syzspec.NewSyzFS(syzkallerRepoRoot(t), "linux"),
	}

	_, err := syzGrepper(nil, state, syzGrepperArgs{
		PathPrefix: "test/non_existent_dir",
		Expression: "SECONDARY_EXEC_SHADOW_VMCS",
	})
	require.Error(t, err)
	require.NotContains(t, err.Error(), syzkallerRepoRoot(t))
}
