// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/stretchr/testify/require"
)

func TestDatabaseIntern(t *testing.T) {
	tempDir := t.TempDir()
	cFile := "main.c"
	err := os.WriteFile(filepath.Join(tempDir, cFile), []byte("line1\nline2\nline3\nline4\nline5\n"), 0644)
	require.NoError(t, err)

	v := clangtool.NewVerifier(tempDir)

	db1 := &Database{
		Definitions: []*Definition{
			{
				Name: "my_func",
				Body: LineRange{File: cFile, StartLine: 1, EndLine: 3},
				Refs: []Reference{
					{Name: strings.Clone("some_symbol")},
					{Name: strings.Clone("another_symbol")},
				},
			},
		},
	}

	db2 := &Database{
		Definitions: []*Definition{
			{
				Name: "my_func2",
				Body: LineRange{File: cFile, StartLine: 2, EndLine: 4},
				Refs: []Reference{
					{Name: strings.Clone("some_symbol")},
					{Name: strings.Clone("another_symbol")},
				},
			},
		},
	}

	mergedDB := &Database{}
	mergedDB.Merge(db1, v)
	mergedDB.Merge(db2, v)
	mergedDB.Finalize(v)

	require.NoError(t, v.Error())

	require.Len(t, mergedDB.Definitions, 2)

	ref1Name := mergedDB.Definitions[0].Refs[0].Name
	ref2Name := mergedDB.Definitions[1].Refs[0].Name
	require.Equal(t, "some_symbol", ref1Name)
	require.Equal(t, "some_symbol", ref2Name)

	ptr1 := unsafe.StringData(ref1Name)
	ptr2 := unsafe.StringData(ref2Name)

	// We must cast the *byte pointers to uintptr before comparing them.
	// require.Equal uses reflect.DeepEqual, which dereferences pointers and
	// compares their values (the characters). Comparing the pointers directly
	// would pass as long as they point to the same character, but casting to
	// uintptr forces it to verify that they share the exact same memory address.
	require.Equal(t, uintptr(unsafe.Pointer(ptr1)), uintptr(unsafe.Pointer(ptr2)), "reference names were not interned")
}
