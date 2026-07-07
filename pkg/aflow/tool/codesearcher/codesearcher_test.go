// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearcher

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/codesearch"
)

func TestStructLayout(t *testing.T) {
	aflow.TestTool(t, ToolStructLayout,
		createIndex(t),
		structLayoutArgs{
			Name: "struct_in_c_file",
		},
		structLayoutResult{
			Fields: []structLayoutField{
				{Name: "X", OffsetBits: 0, SizeBits: 32},
				{Name: "by_value", OffsetBits: 32, SizeBits: 64},
			},
		},
		``,
	)
}

func TestStructLayoutNonExistent(t *testing.T) {
	aflow.TestTool(t, ToolStructLayout,
		createIndex(t),
		structLayoutArgs{
			Name: "non-existent-name",
		},
		structLayoutResult{},
		`requested entity does not exist`,
	)
}

func TestReadFile(t *testing.T) {
	aflow.TestTool(t, ToolReadFile,
		fsState{KernelSrc: filepath.FromSlash("../../../codesearch/testdata")},
		readFileArgs{
			File:      "global_vars.c",
			FirstLine: 11,
			LineCount: 1,
		},
		readFileResult{
			Contents: "  11:\tint global_var = 3;\n",
		},
		``,
	)
}

func TestReadFileNonExistent(t *testing.T) {
	aflow.TestTool(t, ToolReadFile,
		fsState{KernelSrc: filepath.FromSlash("../../../codesearch/testdata")},
		readFileArgs{
			File:      "file-that-does-not-exist.c",
			FirstLine: 1,
			LineCount: 1,
		},
		readFileResult{},
		`the file does not exist`,
	)
}

func TestDirIndex(t *testing.T) {
	aflow.TestTool(t, ToolDirIndex,
		fsState{KernelSrc: filepath.FromSlash("../../../codesearch/testdata")},
		dirIndexArgs{
			Dir: "mm",
		},
		dirIndexResult{
			Subdirs: nil,
			Files:   []string{"refs.c", "slub.c", "slub.h"},
		},
		``,
	)
}

func TestDirIndexNonExistent(t *testing.T) {
	aflow.TestTool(t, ToolDirIndex,
		fsState{KernelSrc: filepath.FromSlash("../../../codesearch/testdata")},
		dirIndexArgs{
			Dir: "dir-that-does-not-exist",
		},
		dirIndexResult{},
		`the directory does not exist`,
	)
}

func TestReadFileEmptySrc(t *testing.T) {
	aflow.TestTool(t, ToolReadFile,
		fsState{KernelSrc: ""},
		readFileArgs{
			File:      "global_vars.c",
			FirstLine: 11,
			LineCount: 1,
		},
		readFileResult{},
		"KernelSrc is empty",
	)
}

func createIndex(t *testing.T) prepareResult {
	return prepareResult{
		Index: index{codesearch.NewTestIndex(t, filepath.FromSlash("../../../codesearch/testdata"))},
	}
}
