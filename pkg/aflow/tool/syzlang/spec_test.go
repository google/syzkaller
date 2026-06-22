// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestDescriptionFiles(t *testing.T) {
	files := DescriptionFiles(targets.Linux)
	require.Greater(t, len(files), 50)
	require.Contains(t, files, "sys.txt")
}

func TestDescriptionFilesPrompt(t *testing.T) {
	prompt := DescriptionFilesPrompt(targets.Linux)
	require.Contains(t, prompt, "sys.txt\n")
	require.NotContains(t, prompt, "sys.txt.const\n")
}

func TestReadSyzSpec(t *testing.T) {
	// Test pagination.
	res, err := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{
		File:      "sys.txt",
		FirstLine: 1,
	})
	require.NoError(t, err)
	require.Contains(t, res.Output, "Copyright")

	// Test missing file.
	_, err2 := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "non_existent_file.txt"})
	require.Error(t, err2)

	// Test invalid file paths.
	_, errInvalid := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "../sys.txt"})
	require.ErrorContains(t, errInvalid, "invalid file path")
	_, errInvalid2 := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "/etc/passwd"})
	require.ErrorContains(t, errInvalid2, "invalid file path")

	// Test reading auto.txt or auto.txt.const is disallowed.
	_, errAuto := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "auto.txt"})
	require.ErrorContains(t, errAuto, "access to auto.txt or auto.txt.const is disallowed")
	_, errAutoConst := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "auto.txt.const"})
	require.ErrorContains(t, errAutoConst, "access to auto.txt or auto.txt.const is disallowed")

	// Test reading const file works.
	resConst, errConst := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{File: "aio.txt.const", FirstLine: 1})
	require.NoError(t, errConst)
	require.NotEmpty(t, resConst.Output)

	// Test pagination boundary violation.
	_, errBound := readSyzSpec(nil, specToolsState{}, readSyzSpecArgs{
		File:      "sys.txt",
		FirstLine: 9999999, // Way out of bounds.
	})
	require.ErrorContains(t, errBound, "does not have line")

	// Test reading test seed file.
	resSeed, errSeed := readSyzSpec(nil, specToolsState{Syzkaller: "../../../.."}, readSyzSpecArgs{
		File:      "test/syz_mount_image_btrfs_0",
		FirstLine: 1,
	})
	require.NoError(t, errSeed)
	require.NotEmpty(t, resSeed.Output)

	// Add temp directory for Syzkaller repo simulation.
	state := specToolsState{Syzkaller: "../../../.."}

	// Test pagination of mock file inside executor/.
	resExec, errExec := readSyzSpec(nil, state, readSyzSpecArgs{
		File:      "executor/common.h",
		FirstLine: 1,
	})
	require.NoError(t, errExec)
	require.Contains(t, resExec.Output, "doexit_thread")

	// Test rejection of path traversal attempts.
	_, errTrav := readSyzSpec(nil, state, readSyzSpecArgs{File: "executor/../../configs/something.conf"})
	require.ErrorContains(t, errTrav, "invalid file path")
}

func TestSyzGrepper(t *testing.T) {
	// Test grep with a file.
	resGrep, errGrep := syzGrepper(nil, specToolsState{}, syzGrepperArgs{
		PathPrefix: "sys.txt",
		Expression: "^type ",
	})
	require.NoError(t, errGrep)
	require.Contains(t, resGrep.Output, "type ")
	require.Contains(t, resGrep.Output, ":\ttype")

	// Test grep across all files.
	resGrepAll, errGrepAll := syzGrepper(nil, specToolsState{}, syzGrepperArgs{
		Expression: "^type ",
	})
	require.NoError(t, errGrepAll)
	require.Contains(t, resGrepAll.Output, ".txt:")
	require.Contains(t, resGrepAll.Output, "type")

	// Test grep with no matches (should return success, not error).
	resEmpty, errEmpty := syzGrepper(nil, specToolsState{}, syzGrepperArgs{
		PathPrefix: "sys.txt",
		Expression: "THIS_STRING_SHOULD_NOT_EXIST_IN_SYS_TXT",
	})
	require.NoError(t, errEmpty)
	require.Equal(t, "No matches found.", resEmpty.Output)

	// Test grep across test seed file.
	resSeedGrep, errSeedGrep := syzGrepper(nil, specToolsState{Syzkaller: "../../../.."}, syzGrepperArgs{
		PathPrefix: "test/syz_mount_image_btrfs_0",
		Expression: "syz_mount_image",
	})
	require.NoError(t, errSeedGrep)
	require.Contains(t, resSeedGrep.Output, "syz_mount_image")

	state := specToolsState{Syzkaller: "../../../.."}

	// Test grepping across files in executor/.
	resExecGrep, errExecGrep := syzGrepper(nil, state, syzGrepperArgs{
		PathPrefix: "executor/common.h",
		Expression: "doexit_thread",
	})
	require.NoError(t, errExecGrep)
	require.Contains(t, resExecGrep.Output, "doexit_thread")
}
