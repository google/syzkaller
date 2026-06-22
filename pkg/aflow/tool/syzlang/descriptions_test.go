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

func TestReadDescription(t *testing.T) {
	// Test pagination.
	res, err := readDescription(nil, readDescState{}, readDescArgs{
		File:      "sys.txt",
		FirstLine: 1,
	})
	require.NoError(t, err)
	require.Contains(t, res.Output, "Copyright")

	// Test missing file without expression.
	_, err2 := readDescription(nil, readDescState{}, readDescArgs{File: "non_existent_file.txt"})
	require.Error(t, err2)

	// Test invalid file paths.
	_, errInvalid := readDescription(nil, readDescState{}, readDescArgs{File: "../sys.txt"})
	require.ErrorContains(t, errInvalid, "invalid file path")
	_, errInvalid2 := readDescription(nil, readDescState{}, readDescArgs{File: "/etc/passwd"})
	require.ErrorContains(t, errInvalid2, "invalid file path")

	// Test reading auto.txt or auto.txt.const is disallowed.
	_, errAuto := readDescription(nil, readDescState{}, readDescArgs{File: "auto.txt"})
	require.ErrorContains(t, errAuto, "access to auto.txt or auto.txt.const is disallowed")
	_, errAutoConst := readDescription(nil, readDescState{}, readDescArgs{File: "auto.txt.const"})
	require.ErrorContains(t, errAutoConst, "access to auto.txt or auto.txt.const is disallowed")

	// Test reading const file works.
	resConst, errConst := readDescription(nil, readDescState{}, readDescArgs{File: "aio.txt.const", FirstLine: 1})
	require.NoError(t, errConst)
	require.NotEmpty(t, resConst.Output)

	// Test grep with a file.
	resGrep, errGrep := readDescription(nil, readDescState{}, readDescArgs{
		File:       "sys.txt",
		Expression: "^type ",
	})
	require.NoError(t, errGrep)
	require.Contains(t, resGrep.Output, "type ")
	require.Contains(t, resGrep.Output, ":\ttype")

	// Test grep across all files.
	resGrepAll, errGrepAll := readDescription(nil, readDescState{}, readDescArgs{
		Expression: "^type ",
	})
	require.NoError(t, errGrepAll)
	require.Contains(t, resGrepAll.Output, ".txt:")
	require.Contains(t, resGrepAll.Output, "type")

	// Test grep with no matches (should return success, not error).
	resEmpty, errEmpty := readDescription(nil, readDescState{}, readDescArgs{
		File:       "sys.txt",
		Expression: "THIS_STRING_SHOULD_NOT_EXIST_IN_SYS_TXT",
	})
	require.NoError(t, errEmpty)
	require.Equal(t, "No matches found.", resEmpty.Output)

	// Test conflicting arguments.
	_, errConflict := readDescription(nil, readDescState{}, readDescArgs{
		Expression: "^type ",
		FirstLine:  1,
	})
	require.ErrorContains(t, errConflict, "Expression cannot be used together")

	// Test pagination boundary violation.
	_, errBound := readDescription(nil, readDescState{}, readDescArgs{
		File:      "sys.txt",
		FirstLine: 9999999, // Way out of bounds.
	})
	require.ErrorContains(t, errBound, "does not have line")

	// Test reading test seed file.
	resSeed, errSeed := readDescription(nil, readDescState{}, readDescArgs{
		File:      "test/syz_mount_image_btrfs_0",
		FirstLine: 1,
	})
	require.NoError(t, errSeed)
	require.NotEmpty(t, resSeed.Output)

	// Test grep across test seed file.
	resSeedGrep, errSeedGrep := readDescription(nil, readDescState{}, readDescArgs{
		File:       "test/syz_mount_image_btrfs_0",
		Expression: "syz_mount_image",
	})
	require.NoError(t, errSeedGrep)
	require.Contains(t, resSeedGrep.Output, "syz_mount_image")
}
