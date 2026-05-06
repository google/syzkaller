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

func createIndex(t *testing.T) prepareResult {
	return prepareResult{
		Index: index{codesearch.NewTestIndex(t, filepath.FromSlash("../../../codesearch/testdata"))},
	}
}
