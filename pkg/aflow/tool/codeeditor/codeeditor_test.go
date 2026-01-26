// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestCodeeditorEscapingPath(t *testing.T) {
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: "whatever",
		},
		args{
			SourceFile: "../../passwd",
		},
		struct{}{},
		`SourceFile "../../passwd" is outside of the source tree`,
	)
}

func TestCodeeditorMissingPath(t *testing.T) {
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: t.TempDir(),
		},
		args{
			SourceFile: "missing-file",
		},
		struct{}{},
		`SourceFile "missing-file" does not exist`,
	)
}

func TestCodeeditorEmptyCurrentCode(t *testing.T) {
	dir := writeTestFile(t, "foo", "data")
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile: "foo",
		},
		struct{}{},
		`CurrentCode snippet is empty`,
	)
}

func writeTestFile(t *testing.T, filename, data string) string {
	dir := t.TempDir()
	if err := osutil.WriteFile(filepath.Join(dir, filename), []byte(data)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func Fuzz(f *testing.F) {
	dir := f.TempDir()
	const filename = "src.c"
	fullFilename := filepath.Join(dir, filename)
	f.Fuzz(func(t *testing.T, fileData []byte, curCode, newCode string) {
		require.NoError(t, osutil.WriteFile(fullFilename, fileData))
		aflow.FuzzTool(t, Tool,
			state{
				KernelScratchSrc: dir,
			},
			args{
				SourceFile:  filename,
				CurrentCode: curCode,
				NewCode:     newCode,
			})
	})
}
