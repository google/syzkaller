// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestCodeeditorEscapingPath(t *testing.T) {
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: t.TempDir(),
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

func TestCodeeditorNonSourceFile(t *testing.T) {
	dir := writeTestFile(t, "src", "data")
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile: "src",
		},
		struct{}{},
		`SourceFile "src" does not exist`,
	)
}

func TestCodeeditorEmptyCurrentCode(t *testing.T) {
	dir := writeTestFile(t, "src.c", "data")
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile: "src.c",
		},
		struct{}{},
		`CurrentCode snippet is empty`,
	)
}

func TestCodeeditorNoMatches(t *testing.T) {
	dir := writeTestFile(t, "src.c", "foo")
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile:  "src.c",
			CurrentCode: "foobar",
		},
		struct{}{},
		`CurrentCode snippet does not match anything in the source file, provide more precise CurrentCode snippet`,
	)
}

func TestCodeeditorMultipleMatches(t *testing.T) {
	dir := writeTestFile(t, "src.c", `
linefoo
bar
foo
bar
foo
fooline
foo`)
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile:  "src.c",
			CurrentCode: "foo",
		},
		struct{}{},
		`CurrentCode snippet matched 3 places, increase context in CurrentCode to avoid ambiguity`,
	)
}

func TestCodeeditorNopEdit(t *testing.T) {
	dir := writeTestFile(t, "src.c", `
line0
line1
`)
	aflow.TestTool(t, Tool,
		state{
			KernelScratchSrc: dir,
		},
		args{
			SourceFile:  "src.c",
			CurrentCode: "  line0",
			NewCode:     "line0",
		},
		struct{}{},
		`The edit does not change the code.`,
	)
}

func TestCodeeditorReplacement(t *testing.T) {
	type Test struct {
		curFile string
		curCode string
		newCode string
		newFile string
	}
	tests := []Test{
		{
			curFile: `
line0
line1
lineee2
lin3
last line
`,
			curCode: `line1
lineee2
lin3`,
			newCode: `replaced line`,
			newFile: `
line0
replaced line
last line
`,
		},
		{
			curFile: `
line0
line1
last line
`,
			curCode: `line1
`,
			newCode: `replaced line 1
replaced line 2
replaced line 3`,
			newFile: `
line0
replaced line 1
replaced line 2
replaced line 3
last line
`,
		},
		{
			curFile: `
line0
line1
line2
`,
			curCode: `line2
`,
			newCode: ``,
			newFile: `
line0
line1
`,
		},
		{
			curFile: `that's it`,
			curCode: `that's it`,
			newCode: `that's that`,
			newFile: `that's that
`,
		},
		{
			curFile: `
	line0
	line1
	
	  line2
line3

line4
`,
			curCode: `
line1
	line2  	
	

  line3 `,
			newCode: `  replacement`,
			newFile: `
	line0
  replacement

line4
`,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			const filename = "src.c"
			dir := writeTestFile(t, filename, test.curFile)
			aflow.TestTool(t, Tool,
				state{
					KernelScratchSrc: dir,
				},
				args{
					SourceFile:  filename,
					CurrentCode: test.curCode,
					NewCode:     test.newCode,
				},
				struct{}{},
				"")
			data, err := os.ReadFile(filepath.Join(dir, filename))
			require.NoError(t, err)
			require.Equal(t, test.newFile, string(data))
		})
	}
}

func writeTestFile(t *testing.T, filename, data string) string {
	dir := t.TempDir()
	require.NoError(t, osutil.WriteFile(filepath.Join(dir, filename), []byte(data)))
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
