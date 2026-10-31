// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
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

func TestCodeeditorCreateFile(t *testing.T) {
	for _, filename := range []string{"new.c", "include/new.h", ":new.c"} {
		t.Run(filename, func(t *testing.T) {
			dir := osutil.SandboxTempDir(t)
			t.Setenv("HOME", dir)
			repo := vcs.MakeTestRepo(t, filepath.Join(dir, "repo"))
			repo.CommitChangeset("initial commit", vcs.FileContent{
				File:    "old.c",
				Content: "/* existing file */\n",
			})
			file := filepath.Join(repo.Dir, filename)
			require.NoError(t, os.MkdirAll(filepath.Dir(file), osutil.DefaultDirPerm))
			require.NoError(t, osutil.SandboxChown(filepath.Dir(file)))
			aflow.TestTool(t, Tool, state{repo.Dir}, args{
				SourceFile: filename,
				NewCode:    "int value;",
			}, struct{}{}, "")
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Equal(t, "int value;\n", string(data))
			t.Run("ownership", func(t *testing.T) {
				osutil.RequireSandbox(t)
				assert.True(t, osutil.IsSandboxOwned(t, file))
			})
			// Creation must not silently overwrite a file that already exists.
			aflow.TestTool(t, Tool, state{repo.Dir}, args{
				SourceFile: filename,
				NewCode:    "int replacement;",
			}, struct{}{}, "CurrentCode snippet is empty")
			// A new file remains editable using the normal replacement tool.
			aflow.TestTool(t, Tool, state{repo.Dir}, args{
				SourceFile:  filename,
				CurrentCode: "int value;",
				NewCode:     "int updated;",
			}, struct{}{}, "")
			diff, err := patchdiff.Diff(repo.Dir, "HEAD")
			require.NoError(t, err)
			assert.Contains(t, diff, "new file mode 100644")
			assert.Contains(t, diff, "+++ b/"+filename)
			assert.Contains(t, diff, "+int updated;\n")
			// The patch must also be consumable by the rest of the patching workflow.
			other := vcs.MakeTestRepo(t, filepath.Join(dir, "other"))
			other.CommitChangeset("initial commit", vcs.FileContent{
				File:    "old.c",
				Content: "/* existing file */\n",
			})
			require.NoError(t, vcs.SandboxedGit(other.Dir).Apply([]byte(diff)))
			data, err = os.ReadFile(filepath.Join(other.Dir, filename))
			require.NoError(t, err)
			assert.Equal(t, "int updated;\n", string(data))
		})
	}
}

func TestCodeeditorCreateFileInvalid(t *testing.T) {
	for _, test := range []struct {
		name string
		args args
	}{
		{"empty", args{SourceFile: "new.c"}},
		{"whitespace", args{SourceFile: "new.c", NewCode: " \n"}},
		{"missing-current", args{SourceFile: "new.c", CurrentCode: "old", NewCode: "new"}},
		{"missing-parent", args{SourceFile: "missing/new.c", NewCode: "new"}},
		{"not-a-repo", args{SourceFile: "new.c", NewCode: "new"}},
		{"non-source", args{SourceFile: ".git/config", NewCode: "new"}},
		{"escaping-path", args{SourceFile: "../new.c", NewCode: "new"}},
		{"absolute-path", args{SourceFile: "/new.c", NewCode: "new"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := aflow.TestToolRun(Tool, map[string]any{"KernelScratchSrc": dir}, map[string]any{
				"SourceFile":  test.args.SourceFile,
				"CurrentCode": test.args.CurrentCode,
				"NewCode":     test.args.NewCode,
			})
			require.Error(t, err)
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

func TestCodeeditorCreateFileSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	for _, test := range []struct {
		name   string
		target string
	}{
		{"outside", filepath.Join(outside, "new.c")},
		{"dangling", "target.c"},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := test.name + ".c"
			require.NoError(t, os.Symlink(test.target, filepath.Join(dir, name)))
			_, err := aflow.TestToolRun(Tool, map[string]any{"KernelScratchSrc": dir}, map[string]any{
				"SourceFile": name, "CurrentCode": "", "NewCode": "int value;",
			})
			require.Error(t, err)
			assert.NoFileExists(t, filepath.Join(dir, "target.c"))
			assert.NoFileExists(t, filepath.Join(outside, "new.c"))
		})
	}
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

// nolint:dupl // These test cases have similar structure but different data.
func TestReplace(t *testing.T) {
	tests := []struct {
		name      string
		lines     [][]byte
		src       [][]byte
		dst       [][]byte
		fuzzy     bool
		wantLines [][]byte
		wantMatch int
	}{
		{
			name: "exact_match_single",
			lines: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
				[]byte("line2"),
			},
			src: [][]byte{
				[]byte("line1"),
			},
			dst: [][]byte{
				[]byte("replaced"),
			},
			fuzzy: false,
			wantLines: [][]byte{
				[]byte("line0"),
				[]byte("replaced"),
				[]byte("line2"),
			},
			wantMatch: 1,
		},
		{
			name: "exact_match_multi",
			lines: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
				[]byte("line2"),
				[]byte("line3"),
			},
			src: [][]byte{
				[]byte("line1"),
				[]byte("line2"),
			},
			dst: [][]byte{
				[]byte("replaced1"),
				[]byte("replaced2"),
			},
			fuzzy: false,
			wantLines: [][]byte{
				[]byte("line0"),
				[]byte("replaced1"),
				[]byte("replaced2"),
				[]byte("line3"),
			},
			wantMatch: 1,
		},
		{
			name: "no_match",
			lines: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
			},
			src: [][]byte{
				[]byte("nomatch"),
			},
			dst: [][]byte{
				[]byte("replaced"),
			},
			fuzzy: false,
			wantLines: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
			},
			wantMatch: 0,
		},
		{
			name: "multiple_matches",
			lines: [][]byte{
				[]byte("foo"),
				[]byte("bar"),
				[]byte("foo"),
			},
			src: [][]byte{
				[]byte("foo"),
			},
			dst: [][]byte{
				[]byte("baz"),
			},
			fuzzy: false,
			wantLines: [][]byte{
				[]byte("baz"),
				[]byte("bar"),
				[]byte("baz"),
			},
			wantMatch: 2,
		},
		{
			name: "fuzzy_match_whitespace",
			lines: [][]byte{
				[]byte("  line0  "),
				[]byte("line1"),
			},
			src: [][]byte{
				[]byte("line0"),
			},
			dst: [][]byte{
				[]byte("replaced"),
			},
			fuzzy: true,
			wantLines: [][]byte{
				[]byte("replaced"),
				[]byte("line1"),
			},
			wantMatch: 1,
		},
		{
			name: "fuzzy_match_empty_src_line",
			lines: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
			},
			src: [][]byte{
				[]byte("line0"),
				[]byte(""),
				[]byte("line1"),
			},
			dst: [][]byte{
				[]byte("replaced"),
			},
			fuzzy: true,
			wantLines: [][]byte{
				[]byte("replaced"),
			},
			wantMatch: 1,
		},
		{
			name: "fuzzy_match_empty_file_line",
			lines: [][]byte{
				[]byte("line0"),
				[]byte(""),
				[]byte("line1"),
			},
			src: [][]byte{
				[]byte("line0"),
				[]byte("line1"),
			},
			dst: [][]byte{
				[]byte("replaced"),
			},
			fuzzy: true,
			wantLines: [][]byte{
				[]byte("replaced"),
			},
			wantMatch: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLines, gotMatch := replace(tt.lines, tt.src, tt.dst, tt.fuzzy)
			require.Equal(t, tt.wantMatch, gotMatch)
			require.Equal(t, tt.wantLines, gotLines)
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
